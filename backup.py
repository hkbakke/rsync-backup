#!/usr/bin/env python3

import argparse
import configparser
import logging
import os
import fnmatch
import sys
import hashlib
import subprocess
import re
from datetime import datetime
from shutil import rmtree, copytree, move
import smtplib
from email.mime.text import MIMEText
from functools import partial


LOG = logging.getLogger('log')
LOG.setLevel(logging.DEBUG)
LOG_CLEAN = logging.getLogger('log_clean')
LOG_CLEAN.setLevel(logging.DEBUG)


class BackupException(Exception):
    pass


class Backup(object):
    def __init__(self, configfile, quiet):
        current_datetime = datetime.now()
        self.config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation())
        self.config.read_file(open(configfile))
        self.rules = configfile.replace('.conf', '.rules')
        self.pid_created = False
        self.status = 11
        self.timestamp = current_datetime.strftime('%Y-%m-%d-%H%M%S')
        self.log_file = os.path.join(
            self.config.get('general', 'log_dir'), '%s.log' % self.timestamp)
        self.to_addrs = set(self.config.get('reporting', 'to_addrs').split(','))
        self.pidfile = '/var/run/backup/backup-%s.pid' % (
            self.config.get('general', 'backuplabel'))
        self.cache_dir = os.path.normpath(
            os.path.join(self.config.get('general', 'backuproot'), 'cache'))
        self.checksum_filename = 'checksums.md5'

        # Load status mapping
        self.statuses = {
            10: 'Backup completed successfully!',
            11: 'Backup failed!',
            12: 'Backup aborted by user!',
            14: 'Backup verification completed successfully!',
            15: 'Backup verification failed!',
            17: 'Unknown status',
        }

        # Configure default values for backup intervals
        self.intervals = {
            'current': {
                'retention': 1
            },
            'daily': {
                'retention': self.config.getint(
                    'retention', 'daily', fallback=30),
                'pattern': '%s-*' % current_datetime.strftime('%Y-%m-%d')
            },
            'monthly': {
                'retention': self.config.getint(
                    'retention', 'monthly', fallback=36),
                'pattern': '%s-*' % current_datetime.strftime('%Y-%m')
            },
            'yearly': {
                'retention': self.config.getint(
                    'retention', 'yearly', fallback=5),
                'pattern': '%s-*' % current_datetime.strftime('%Y')
            }
        }

        # Check if backup is already running and set up logging
        self._is_running()
        self._create_dirs()
        self._prepare_logging(quiet)

    @staticmethod
    def _get_files_recursive(path):
        for root, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if os.path.isfile(file_path) and not os.path.islink(file_path):
                    yield file_path

    @staticmethod
    def _parse_checksum_file(checksum_file):
        with open(checksum_file, 'rb') as f:
            for line in f:
                checksum, filename = line.split(None, 1)
                filename = filename.strip()
                yield checksum, filename

    @staticmethod
    def _get_file_md5(filename):
        """
        Return bytes instead of a string as bytes is used in all
        other checksum file operations because filenames are bytes without
        encoding in Linux
        """
        md5 = hashlib.md5()
        chunksize = 128*512
        with open(filename, 'rb') as f:
            for chunk in iter(partial(f.read, chunksize), b''):
                md5.update(chunk)
        return bytes(md5.hexdigest(), 'utf8')

    @staticmethod
    def _get_line_count(filename, unique=False):
        with open(filename, 'rb') as f:
            if unique:
                linecount = len(set(f.readlines()))
            else:
                linecount = len(f.readlines())
        return linecount

    @staticmethod
    def _get_file_count_recursive(path):
        count = 0
        for root, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if os.path.isfile(file_path) and not os.path.islink(file_path):
                    count += 1
        return count

    @staticmethod
    def _create_dir(directory):
        if not os.path.exists(directory):
            os.makedirs(directory)

    @staticmethod
    def _get_timestamp_from_file(file_path):
        timestamp_datetime = None
        try:
            with open(file_path, 'r') as f:
                timestamp_datetime = datetime.strptime(
                    f.readline().strip(), '%Y-%m-%d %H:%M:%S')
        except IOError:
            pass
        except ValueError:
            os.unlink(file_path)
        return timestamp_datetime

    @staticmethod
    def _run_rsync(rsync_command):
        checksums = list()
        p = subprocess.Popen(
            rsync_command, shell=False, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        while p.poll() is None:
            for line in iter(p.stdout.readline, b''):
                line = line.strip()
                LOG_CLEAN.info(line.decode('utf8'))

                # Extract md5 checksum from rsync output for new or
                # changed files
                if re.match(b'^>', line):
                    rsync_update_info = line.split(b' ', 2)
                    file_checksum = rsync_update_info[1]
                    file_path = b'./' + rsync_update_info[2]
                    checksums.append([file_path, file_checksum])

        exit_code = p.returncode
        if exit_code != 0:
            raise BackupException(
                'Rsync returned non-zero exit code [ %s ]' % exit_code)

        return checksums

    @staticmethod
    def _write_checksum_file(checksum_file, checksums):
        LOG.info('Adding %d md5 checksums to %s', len(checksums), checksum_file)
        with open(checksum_file, 'wb') as f:
            for filename, checksum in checksums:
                f.write(checksum + b'  ' + filename + b'\n')

    @staticmethod
    def _get_end_status_from_log_file(log_file):
        with open(log_file, 'r') as f:
            lastline = f.readlines()[-1]
            if 'END STATUS:' in lastline:
                return int(lastline.split()[-1])
            else:
                return 17

    @staticmethod
    def _get_log_file_datetime(log_file):
        timestamp = re.search(r'([0-9-]{17}).log$', log_file)
        if timestamp:
            return datetime.strptime(timestamp.group(1), '%Y-%m-%d-%H%M%S')

    @staticmethod
    def _get_backup_for_checksum_file(checksum_file):
        backup = os.path.join(os.path.dirname(checksum_file), 'backup')
        if os.path.exists(backup):
            return backup

    @staticmethod
    def _write_timestamp_to_file(file_path):
        with open(file_path, 'w') as f:
            f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    def _create_dirs(self):
        self._create_dir(self.config.get('general', 'backuproot'))
        self._create_dir(self.config.get('general', 'log_dir'))
        self._create_dir(self.cache_dir)

    def _cleanup(self):
        if self.pid_created:
            os.remove(self.pidfile)

    def _prepare_logging(self, quiet):
        formatter = logging.Formatter(
            '%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S ->')
        no_format = logging.Formatter('%(message)s')

        # Create file handler for logging to file
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(formatter)
        LOG.addHandler(fh)

        fh_clean = logging.FileHandler(self.log_file)
        fh_clean.setFormatter(no_format)
        LOG_CLEAN.addHandler(fh_clean)

        # Create console handler for logging to console, unless quiet is set
        if not quiet:
            ch = logging.StreamHandler()
            ch.setFormatter(formatter)
            LOG.addHandler(ch)

            ch_clean = logging.StreamHandler()
            ch_clean.setFormatter(no_format)
            LOG_CLEAN.addHandler(ch_clean)

    def schedule_verification(self):
        if self.config.getint('general', 'days_between_verifications') == 0:
            LOG.warning(
                'Automatic backup verification is disabled. '
                'This is NOT recommended!')
            return

        last_verification_file = os.path.join(
            self.cache_dir, 'last_verification')
        last_verified = self._get_timestamp_from_file(last_verification_file)
        if not last_verified:
            self._write_timestamp_to_file(last_verification_file)
            return

        days_since_verification = (datetime.now() - last_verified).days
        if (days_since_verification >
                self.config.getint('general', 'days_between_verifications')):
            LOG.info(
                'At least %d days have passed since the backup was last '
                'verified. Initializing verification...',
                self.config.getint('general', 'days_between_verifications'))
            if self.verify():
                self._write_timestamp_to_file(last_verification_file)

    def _validate_checksum_file(self, checksum_file):
        if not os.path.isfile(checksum_file):
            raise BackupException('The file %s does not exist' % checksum_file)

        backup_dir = self._get_backup_for_checksum_file(checksum_file)
        if not backup_dir:
            raise BackupException(
                'Could not find a valid backup for %s' % checksum_file)

        checksum_file_unique_files = self._get_line_count(checksum_file, True)
        checksum_file_files = self._get_line_count(checksum_file)
        backup_file_count = self._get_file_count_recursive(backup_dir)

        if checksum_file_unique_files != checksum_file_files:
            raise BackupException(
                'There are %d lines in %s, but only %d are unique. '
                'These counts should be equal.' % (
                    checksum_file_files, checksum_file,
                    checksum_file_unique_files))

        if checksum_file_unique_files != backup_file_count:
            raise BackupException(
                'There are %d lines in %s, while there are %d files in %s. '
                'These counts should be equal.' % (
                    checksum_file_unique_files, checksum_file,
                    backup_file_count, backup_dir))

        return True

    def verify(self, backup_dir='_current_'):
        LOG.info(
            'Initializing checksum verification for %s',
            self.config.get('general', 'backuproot'))
        self.status = 15

        if backup_dir == '_current_':
            backup_dir = self._get_latest_backup()

        checksum_file = self._get_checksum_file(backup_dir)
        if not checksum_file:
            LOG.warning('There is no checksum file to verify for this backup')
            return False

        checksum_file = os.path.abspath(checksum_file)
        LOG.info('Selected checksum file: %s', checksum_file)
        backup_dir = self._get_backup_for_checksum_file(checksum_file)
        self._validate_checksum_file(checksum_file)
        LOG.info('Starting backup verification...')
        checked_count = 0
        verified_count = 0
        failed_count = 0
        failed_files = list()

        for stored_checksum, filename in self._parse_checksum_file(
                checksum_file):
            file_path = os.path.normpath(
                os.path.join(bytes(backup_dir, 'utf8'), filename))
            checked_count += 1
            current_checksum = self._get_file_md5(file_path)
            if current_checksum == stored_checksum:
                verified_count += 1
            else:
                failed_count += 1
                failed_files.append(
                    [file_path, current_checksum, stored_checksum])
                LOG_CLEAN.warning('[ FAILED ] %s', file_path.decode('utf8'))

        # Use tuples in a list instead of a dictionary to make the stats output
        # ordered
        stats = list()
        stats.extend([('Files checked', checked_count)])
        stats.extend([('Successful verifications', verified_count)])
        stats.extend([('Failed verifications', failed_count)])
        self._display_verification_stats(stats)

        if failed_files:
            LOG.warning('Files that failed verification:')
            for file_path, current_checksum, stored_checksum in failed_files:
                LOG_CLEAN.warning(
                    '%s | current: %s | stored: %s', file_path,
                    stored_checksum, current_checksum)
                LOG.error(self.statuses[self.status])
            return False
        else:
            self.status = 14
            LOG.info(self.statuses[self.status])
            return True

    def _display_verification_stats(self, stats):
        label_width = 26
        LOG_CLEAN.info('')
        for line in stats:
            LOG_CLEAN.info(
                '{0}: {1}'.format(line[0].ljust(label_width), line[1]))
        LOG_CLEAN.info('')

    def _configure_rsync(self, dest_dir, test=False):
        rsync = self.config.get('rsync', 'pathname', fallback='rsync')
        command = [rsync, '-avihh', '--stats', '--out-format=%i %C %n%L']
        command.extend(self.config.get('rsync', 'additional_options').split())

        if test:
            command.extend(['-n'])

        if self.config.get('rsync', 'mode') == 'ssh':
            source = '%s@%s:%s' % (
                self.config.get('rsync', 'ssh_user'),
                self.config.get('rsync', 'source_host'),
                self.config.get('rsync', 'source_dir'))
            command.extend(
                ['-e', 'ssh -i %s' % self.config.get('rsync', 'ssh_key')])
        elif self.config.get('rsync', 'mode') == 'local':
            source = self.config.get('rsync', 'source_dir')
        else:
            raise BackupException(
                '%s is not a valid value for MODE' %
                self.config.get('rsync', 'mode'))

        if not os.path.isfile(self.rules):
            raise BackupException('%s does not exist' % self.rules)
        command.extend(['-f', 'merge %s' % self.rules])

        # Check if previous backup exists and use this for hardlinking
        previous_backup = self._get_latest_backup()
        if previous_backup:
            command.append('--link-dest=%s' % previous_backup)

        # Continue previously incomplete backup if available
        incomplete_backup = self._get_incomplete_backup()

        if incomplete_backup:
            LOG.info(
                'Incomplete backup found in %s. Resuming...',
                incomplete_backup)

            if test:
                dest_dir = incomplete_backup
            else:
                move(incomplete_backup, os.path.dirname(dest_dir))

            command.append('--delete-excluded')
        else:
            if not test:
                self._create_dir(dest_dir)

        command.extend([source, dest_dir])
        return command

    def do_backup(self, test=False):
        self.status = 11
        dest_dir = os.path.join(
            self.config.get('general', 'backuproot'), 'incomplete_%s' %
            self.timestamp, 'backup')
        rsync_command = self._configure_rsync(dest_dir, test)
        LOG.info(
            'Starting backup labeled \"%s\" to %s',
            self.config.get('general', 'backuplabel'), dest_dir)
        LOG.info(
            'Commmand: %s', ' '.join(element for element in rsync_command))
        rsync_checksums = self._run_rsync(rsync_command)

        if not test:
            checksums = self._get_checksums(dest_dir, rsync_checksums)
            checksum_file = os.path.join(
            os.path.dirname(dest_dir), self.checksum_filename)
            self._write_checksum_file(checksum_file, checksums)

            # Rename incomplete backup to current and enforce retention
            current_backup = os.path.join(
                self.config.get('general', 'backuproot'), 'current_%s' %
                self.timestamp)

            move(os.path.dirname(dest_dir), current_backup)
            self._create_interval_backups(current_backup)
            self._remove_old_backups()
            self._remove_old_log_files()

        self.status = 10
        LOG.info(self.statuses[self.status])

    def _create_interval_backups(self, current_backup):
        for interval in self.intervals:
            if interval == 'current':
                continue

            if self.intervals[interval]['retention'] < 1:
                continue

            already_existing = fnmatch.filter(
                self._get_backups(interval),
                '*_%s' % self.intervals[interval]['pattern'])
            if already_existing:
                continue

            interval_backup = current_backup.replace(
                'current_', '%s_' % interval)
            LOG.info('Creating %s', interval_backup)
            copytree(current_backup, interval_backup, copy_function=os.link)

    def _remove_old_backups(self):
        LOG.info('Removing old backups...')
        for interval in self.intervals:
            old_backups = [i for i in self._get_backups(interval)]
            old_backups.sort(reverse=True)
            for old_backup in old_backups[
                    self.intervals[interval]['retention']:]:
                LOG.info('Removing %s', old_backup)
                rmtree(old_backup)

    def _remove_old_log_files(self):
        retention = self.config.getint('retention', 'logs', fallback=365)
        if retention < 1:
            return

        LOG.info('Removing backup logs older than %d days...', retention)
        old_logs = [i for i in self._get_log_files()]
        old_logs.sort(reverse=True)
        for old_log in old_logs:
            if old_log == self.log_file:
                continue

            log_datetime = self._get_log_file_datetime(old_log)
            if (datetime.now() - log_datetime).days > retention:
                LOG.info('Removing %s', old_log)
                os.unlink(old_log)

    def _get_checksums(self, backup_dir, rsync_checksums):
        backup_dir = bytes(backup_dir, 'utf8')
        current_files = {
            re.sub(re.escape(backup_dir), b'.', filename, 1)
            for filename in self._get_files_recursive(backup_dir)}

        checksums = rsync_checksums
        previous_checksum_file = self._get_checksum_file(
            self._get_latest_backup)
        if previous_checksum_file:
            LOG.info(
                'Reusing unchanged checksums from %s', previous_checksum_file)
            unchanged_files = current_files.difference(
                {rsynced_file[0] for rsynced_file in rsync_checksums})

            for file_checksum, file_path in self._parse_checksum_file(
                    previous_checksum_file):
                if file_path in unchanged_files:
                    checksums.append([file_path, file_checksum])

        # Add the rest of the files to the list of files that need their
        # checksums calculated. This is typically files previously
        # transferred in a resumed backup.
        need_checksum = current_files.difference(
            {checksum[0] for checksum in checksums})
        LOG.info(
            'Calculating checksum for %d additional files', len(need_checksum))
        for filename in need_checksum:
            filename_path = os.path.join(backup_dir, filename)
            if os.path.islink(filename_path):
                continue

            if os.path.isfile(filename_path):
                checksum = self._get_file_md5(filename_path)
                checksums.append([filename, checksum])

        return checksums

    def _get_new_log_files(self, last_report):
        log_files_to_report = list()

        for log_file in sorted(self._get_log_files(), reverse=True):
            log_file_datetime = self._get_log_file_datetime(log_file)

            if log_file == self.log_file:
                log_files_to_report.extend([(self.status, log_file)])
                continue

            if log_file_datetime > last_report:
                log_files_to_report.extend([(
                    self._get_end_status_from_log_file(log_file),
                    log_file)])
            else:
                break

        return sorted(
            log_files_to_report,
            key=lambda log_file_status: log_file_status[1],
            reverse=True)

    def _is_running(self):
        pid = str(os.getpid())
        if os.path.isfile(self.pidfile):
            process_check = subprocess.call(
                ['pgrep', '--pidfile', self.pidfile, '-f', sys.argv[0]],
                stdout=open(os.devnull, 'wb'))
            if process_check == 0:
                sys.exit()

        self._create_dir(os.path.dirname(self.pidfile))
        with open(self.pidfile, 'w') as f:
            f.write(pid)
        self.pid_created = True

    def get_status(self):
        return self.status

    def _get_incomplete_backup(self):
        for backup_path in os.listdir(self.config.get('general', 'backuproot')):
            if re.match(r'^incomplete_[0-9-]{17}$', backup_path):
                return os.path.join(
                    self.config.get('general', 'backuproot'), backup_path)

    def _get_backups(self, backup_type):
        for backup_path in os.listdir(self.config.get('general', 'backuproot')):
            if re.match(r'^%s_[0-9-]{17}$' % backup_type, backup_path):
                yield os.path.join(
                    self.config.get('general', 'backuproot'), backup_path)

    def _get_log_files(self):
        for log_file_path in os.listdir(self.config.get('general', 'log_dir')):
            if re.match(r'^[0-9-]{17}.log$', log_file_path):
                yield os.path.join(
                    self.config.get('general', 'log_dir'), log_file_path)

    def _get_latest_backup(self):
        try:
            backup = os.path.join(
                sorted(self._get_backups('current'), reverse=True)[0],
                'backup')
        except IndexError:
            backup = None
        return backup

    def _get_checksum_file(self, backup):
        checksum_file = os.path.join(
            os.path.dirname(backup), self.checksum_filename)
        if os.path.exists(checksum_file):
            return checksum_file

    def _send_mail(self, status, log_files):
        summary = ''
        for end_status, log_file in log_files:
            if self.config.getboolean('reporting', 'link_to_logs'):
                url = '%s/%s' % (
                    self.config.get('reporting', 'logs_baseurl').rstrip('/'),
                    os.path.relpath(
                        log_file, self.config.get('general', 'log_dir')))
                summary = '%s%s: %s [ %s ]\n' % (
                    summary, os.path.splitext(os.path.basename(log_file))[0],
                    self.statuses[end_status], url)
            else:
                summary = '%s%s: %s\n' % (
                    summary, os.path.splitext(os.path.basename(log_file))[0],
                    self.statuses[end_status])

        msgtext = """\
%s: %s

Label: %s
Job:   %s


Summary
=======

%s
""" % (
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'), status,
            self.config.get('general', 'backuplabel'), self.timestamp,
            summary)

        msg = MIMEText(msgtext, 'plain')
        msg['Subject'] = '%s [%s: %s]' % (
            status, self.config.get('general', 'backuplabel'), self.timestamp)
        msg['From'] = self.config.get('reporting', 'from_addr')
        msg['To'] = ','.join(addr for addr in self.to_addrs)

        sender = smtplib.SMTP('localhost')
        sender.sendmail(
            self.config.get('reporting', 'from_addr'), self.to_addrs,
            msg.as_string())
        sender.quit()

    def report_status(self, success):
        if self.to_addrs == set(['']):
            LOG.info(
                'Mail reporting is disabled. Set "to_addrs" in the '
                'configuration file to enable')
            return

        last_report_file = os.path.join(self.cache_dir, 'last_report')
        last_report = self._get_timestamp_from_file(last_report_file)

        if not success:
            self._send_mail(
                self.statuses[self.status], [(self.status, self.log_file)])
        elif not last_report:
            self._send_mail(
                self.statuses[self.status], [(self.status, self.log_file)])
            self._write_timestamp_to_file(last_report_file)
        elif ((datetime.now() - last_report).days >
                self.config.getint('reporting', 'days_between_reports')):
            log_files = self._get_new_log_files(last_report)
            status = (
                '%d day backup report'
                % self.config.getint('reporting', 'days_between_reports'))
            self._send_mail(status, log_files)
            self._write_timestamp_to_file(last_report_file)


def main():
    # Get script arguments
    parser = argparse.ArgumentParser(
        description='Rsync based backup with checksumming and reporting.')
    parser.add_argument(
        '-c', '--config-name', metavar='NAME',
        help='Set the name of the configuration to use.', required=True)
    parser.add_argument(
        '-q', '--quiet', help='Suppress output from script.',
        action='store_true')
    parser.add_argument(
        '-i', '--verify', metavar='PATH', nargs='?', const='_current_',
        help='Verify the integrity of the selected backup. If no PATH is '
            'given the current backup is selected.')
    parser.add_argument(
        '-t', '--test', help='Dry run backup. Only logs will be written.',
        action='store_true')
    args = parser.parse_args()

    # Find path to configuration file
    configfile = os.path.join(
        os.path.dirname(os.path.abspath(sys.argv[0])), 'conf.d',
        '%s.conf' % args.config_name)

    # Initialize the backup object
    backup = Backup(configfile, args.quiet)
    success = False

    try:
        if args.verify:
            backup.verify(args.verify)
        else:
            backup.do_backup(args.test)
            if not args.test:
                backup.schedule_verification()

        success = True
    except KeyboardInterrupt:
        LOG.error('Aborted by user')
        backup.status = 12
    except BackupException as e:
        LOG.error(str(e))
    finally:
        if not args.test:
            backup.report_status(success)
        LOG_CLEAN.info('END STATUS: %d', backup.get_status())


if __name__ == '__main__':
    main()
