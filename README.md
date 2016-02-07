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

rsync-backup implements a configurable snapshot, daily, monthly and yearly
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

The latest backup is automatically verified within a user defined interval, 
and every backup can also be verified at will.

## Requirements
* Rsync >= 3.1.0
* Python >= 3.2 (only tested with 3.4 and higher)
* If python > 3.5: scandir module from PyPI

## Usage
### Configure SSH-keys
Generate a SSH key pair for backups and place the public key in 
`~/.ssh/authorized_keys` for the backup user on the source host.
Configure the path to the private key in the backup configuration file.

### Create the global configuration file
Place a file called `rsync-backup.conf` in the directory root. An example
config is included for reference.

### Create the configuration and rules files
Place a configuration file and a rsync rules-file in the conf.d directory for
each backup job. Please see the example files for additional
explanations.

* The configuration file must be called: `<config>.conf`
* The rsync rules file must be called: `<config>.rules`

### Manual run
Run all configured backups:

    ./backup.py -a
Run a specific backup configuration:

    ./backup.py -c <config>
Verify the latest backup:

    ./backup.py -c <config> -i
Verify a specific backup:

    ./backup.py -c <config> -i monthly_2015-04-01-010005
Dry run backup:

    ./backup.py -c <config> -t
Additional features:

    ./backup.py --help 

### Note about parallel backups
By default rsync-backup is doing 2 backups in parallel when not specifying a
specific backup to prevent a single long running backup from blocking all
other backups from running. The number of parallel processes can be configured
with the `-p N` argument. Parallel runs will cause the log output from the 
different backups to interleave with each other as they are printed to the
screen. If this is not acceptable you can disable the parallelization by
setting `-p 1`, effectively making rsync-backup process the backups
sequentially.

The file based logs are not affected by the parallelization, as they are
written individually per backup.

### Docker
If you want to run the backup in a docker container you should do something
like this:

Build:

    cd </path/to/rsync-backup>
    docker build -t rsync-backup --rm=true .
Running rsync-backup:

    docker run -i -t --rm \
        --name=rsync-backup \
        -v "<host_data_dir>":"<backup_root>" \
        -v "<host_ssh_dir>":"/root/.ssh" \
        rsync-backup <backup_args>

The volume `host_ssh_dir` needs to hold the private key and will also have the 
`known_hosts` file to avoid having to confirm new SSH host keys for every 
container run. This directory should be dedicated to the docker container, and
not pointed to i.e. the host's `/root/.ssh` folder.
