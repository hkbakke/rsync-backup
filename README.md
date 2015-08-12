# rsync-backup
rsync-backup is a backup script using rsync written in python.
Its purpose is to run all backups efficiently from a central backup server,
including automatic backup verification and email reporting.

## Backup overview
rsync-backup makes use of rsync's hard linking feature to create efficient
backups where unchanged files are linked together between backups, minimizing
the need for extra storage when doing versioned backups. Rsync only copies
changed blocks, so network backups are efficient and fast after the initial
backup.

rsync-backup implements a configurable current, daily, monthly and yearly
scheme to reduce the number of backups when long retention times are
used. The storage requirements are also reduced when using such a scheme
compared to rolling backups with no efficient trimming of older backups.

## Checksum validation
rsync-backup grabs the internal checksums rsync is generating when transferring
new files to avoid having to calculate the checksums manually. It also 
reuses all checksums for unchanged files from the previous backup, so in most 
cases no additional work is needed for a backup.
It is however smart enough to detect if some files are missing its checksum
and manually calculates the checksum for these files.
This typically happens if a backup is stopped before completion and later
resumed.

The backup's checksum file is stored in each backup folder and is generated in
a md5sum compatible way, so the folder structure can easily be verified with
md5sum if the backup script is not available or the backup is moved.

The current backup is automatically verified within a user defined interval, 
and every backup can also be verified at will.

## Email reporting
The reporting currently assumes that localhost is correctly configured for
SMTP and that it handles the forwarding to the correct SMTP-server for external
communication.

## Requirements
* Rsync >= 3.1.0
* Python >= 3.2 (only tested with 3.4 and higher)

## Usage
### Configure SSH-keys
Generate a SSH-key pair for backups and place the public key in 
`~/.ssh/authorized_keys` for the backup user on the target host.
Configure the path to the private key in the backup configuration file.

### Create a configuration and rules file
Place a configuration file and a rsync rules-file in the conf.d directory for
each backup job. Please see the example configuration file for additional
explanations.

* The configuration file must be called: `<config>.conf`
* The rsync rules file must be called: `<config>.rules`

### Manual run
Standard backup:

    ./backup.py -c <config>
Verify the current backup:

    ./backup.py -c <config> -i
Additional features:

    ./backup.py --help 

### Automatic runs
There is a run-all.sh script included. This script is meant for running
all configured backups with configurable concurrency, and is typically what
you call from cron.

crontab example:

    00 01   * * *       /root/rsync-backup/run-all.sh
