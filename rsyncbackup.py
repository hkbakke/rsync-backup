import configparser
import logging
import os
import fnmatch
import sys
import hashlib
import subprocess
import re
import gzip
import scandir
from datetime import datetime
from shutil import move
import smtplib
from email.mime.text import MIMEText
from functools import partial


class BackupException(Exception):
    pass


class Backup(object):
    def __init__(self, config_name, test=False):
        self.logger = logging.getLogger('%s.%s' % (__name__, config_name))
        self.logger.setLevel(logging.DEBUG)

        self.error = True
        self.migrated = False
        self.status = 'Backup failed!'
        self.pid_created = False
        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

        # Load the global configuration file
        configfile_global = os.path.join(script_dir, 'rsync-backup.conf')
        self.global_config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation())
        self.global_config.read_file(open(configfile_global))

        # Load the backup configuration file
        configfile_backup = os.path.join(script_dir, 'conf.d',
                                         '%s.conf' % config_name)
        self.config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation())
        self.config.read_file(open(configfile_backup))

        self.test = test
        current_datetime = datetime.now()
        self.rules = configfile_backup.replace('.conf', '.rules')
        self.timestamp = current_datetime.strftime('%Y-%m-%d-%H%M%S')
        self.backup_root = os.path.join(
            self.global_config.get('general', 'backup_root'),
            self.config.get('general', 'label'))
        self.log_dir = os.path.join(self.backup_root, 'logs')
        self.log_file = os.path.join(self.log_dir, '%s.log' % self.timestamp)
        self.to_addrs = set(self.config.get(
            'reporting', 'to_addrs',
            fallback=self.global_config.get(
                'reporting', 'to_addrs')).split(','))
        self.pidfile = '/var/run/backup/backup-%s.pid' % (
            self.config.get('general', 'label'))
        self.cache_dir = os.path.join(self.backup_root, 'cache')
        self.backups_dir = os.path.join(self.backup_root, 'backups')
        self.last_verification_file = os.path.join(
            self.cache_dir, 'last_verification')
        self.checksum_file_legacy = 'checksums.md5'
        self.checksum_file = 'checksums.gz'
        self.umask = int(self.global_config.get('general', 'umask',
                                                fallback='0o077'), 8)
        os.umask(self.umask)

        # Configure backup intervals
        self.intervals = {
            'current': {
                'retention': 1
            },
            'daily': {
                'retention': self.config.getint(
                    'retention', 'daily',
                    fallback=self.global_config.getint('retention', 'daily')),
                'pattern': '%s-*' % current_datetime.strftime('%Y-%m-%d')
            },
            'monthly': {
                'retention': self.config.getint(
                    'retention', 'monthly',
                    fallback=self.global_config.getint('retention', 'monthly')),
                'pattern': '%s-*' % current_datetime.strftime('%Y-%m')
            },
            'yearly': {
                'retention': self.config.getint(
                    'retention', 'yearly',
                    fallback=self.global_config.getint('retention', 'yearly')),
                'pattern': '%s-*' % current_datetime.strftime('%Y')
            }
        }

        # Check if backup is already running and set up logging
        self._is_running()
        self._create_dirs()
        self._prepare_logging()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is KeyboardInterrupt:
            self.status = 'Backup aborted!'
            self.logger.error(self.status)
        elif exc_type is not None:
            self.logger.error(exc_value)

        self.cleanup()

    def cleanup(self):
        self.report_status()
        self.logger.info('END STATUS: %s', self.status)

        if self.pid_created:
            os.remove(self.pidfile)

    def _get_files(self, path):
        for entry in scandir.scandir(path):
            if entry.is_file(follow_symlinks=False):
                yield entry.path
            elif entry.is_dir(follow_symlinks=False):
                for dir_file in self._get_files(entry.path):
                    yield dir_file

    def _parse_checksum_file(self, checksum_file):
        if os.path.basename(checksum_file) == self.checksum_file:
            with gzip.open(checksum_file, 'rb') as f:
                for line in f:
                    checksum, filename = line.split(None, 1)
                    filename = filename.strip()

                    yield (filename, checksum)
        elif os.path.basename(checksum_file) == self.checksum_file_legacy:
            with open(checksum_file, 'rb') as f:
                for line in f:
                    checksum, filename = line.split(None, 1)
                    filename = filename.strip()

                    # Remain compatible with old checksum files
                    if filename.startswith(b'./'):
                        filename = filename[len(b'./'):]

                    yield (filename, checksum)

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
    def _create_dir(directory):
        # Use try/except to avoid a race condition between the check for an 
        # existing directory and the creation of a new one when multiple
        # backups running in parallel creates shared directories.
        try:
            os.makedirs(directory)
        except FileExistsError:
            pass

    @staticmethod
    def _get_timestamp(file_path):
        timestamp_datetime = None
        try:
            with open(file_path, 'r') as f:
                timestamp_datetime = datetime.strptime(f.readline().strip(),
                                                       '%Y-%m-%d %H:%M:%S')
        except IOError:
            pass
        except ValueError:
            os.unlink(file_path)
        return timestamp_datetime

    def _run_rsync(self, rsync_command):
        checksums = list()
        p = subprocess.Popen(rsync_command, shell=False,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        while p.poll() is None:
            for line in iter(p.stdout.readline, b''):
                line = line.strip()
                self.logger.info(line.decode('utf8'))

                # Extract md5 checksum from rsync output for new or
                # changed files
                if line.startswith(b'>'):
                    rsync_update_info = line.split(b' ', 2)
                    file_checksum = rsync_update_info[1]
                    file_path = rsync_update_info[2]
                    checksums.append((file_path, file_checksum))

        exit_code = p.returncode
        if exit_code != 0:
            raise BackupException(
                'Rsync returned non-zero exit code [ %s ]' % exit_code)

        return checksums

    def _write_checksum_file(self, checksum_file, checksums):
        if self.test:
            self.logger.info('Adding %d md5 checksums to %s (DRY RUN)',
                             len(checksums), checksum_file)
            return

        self.logger.info('Adding %d md5 checksums to %s', len(checksums),
                         checksum_file)

        with gzip.open(checksum_file, 'wb') as f:
            for filename, checksum in checksums:
                f.write(checksum + b'  ' + filename + b'\n')

    @staticmethod
    def _get_end_status(log_file):
        with open(log_file, 'r') as f:
            lastline = f.readlines()[-1]
            if 'END STATUS:' in lastline:
                return lastline.split('END STATUS: ')[1].strip()
            else:
                return 'Unknown status'

    @staticmethod
    def _get_log_file_datetime(log_file):
        timestamp = re.search(r'([0-9-]{17}).log$', log_file)
        if timestamp:
            return datetime.strptime(timestamp.group(1), '%Y-%m-%d-%H%M%S')

    def _write_timestamp(self, file_path):
        if self.test:
            self.logger.info('Updating timestamp in %s (DRY RUN)', file_path)
            return

        self.logger.info('Updating timestamp in %s', file_path)

        with open(file_path, 'w') as f:
            f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    def _create_dirs(self):
        self._create_dir(self.backup_root)
        self._create_dir(self.backups_dir)
        self._create_dir(self.log_dir)
        self._create_dir(self.cache_dir)

    def _prepare_logging(self):
        std_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s')

        # Create file handler for logging to file
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(std_format)
        self.logger.addHandler(fh)

    def schedule_verification(self):
        self.error = True

        interval = self.config.getint('general', 'verification_interval',
                                      fallback=self.global_config.getint(
                                          'general', 'verification_interval'))
        if interval == 0:
            self.logger.warning('Automatic backup verification is disabled. '
                                'This is NOT recommended!')
            return

        last_verified = self._get_timestamp(
            self.last_verification_file)
        if not last_verified:
            self._write_timestamp(self.last_verification_file)
            return

        days_since_verification = (datetime.now() - last_verified).days
        if (days_since_verification > interval):
            self.logger.info('At least %d days have passed since the backup '
                             'was last verified. Initializing verification...',
                             interval)
            self.verify()

        self.error = False

    def verify(self, backup='_current_'):
        self.status = 'Backup verification failed!'
        self.error = True

        self.logger.info('Initializing checksum verification for %s',
                         self.backup_root)

        if backup == '_current_':
            backup_dir = self._get_latest_backup()
        else:
            backup_dir = self._get_backup_dir(backup)

        if not backup_dir:
            raise BackupException('There is no backup to verify')

        checksum_file = self._get_checksum_file(backup_dir)
        if not checksum_file:
            raise BackupException(
                'There is no checksum file to verify for this backup')

        self.logger.info('Selected checksum file: %s', checksum_file)
        self.logger.info('Starting backup verification...')
        checked_count = 0
        verified_count = 0
        failed_count = 0
        failed_files = list()

        for filename, stored_checksum in self._parse_checksum_file(
                checksum_file):
            file_path = os.path.normpath(
                os.path.join(bytes(backup_dir, 'utf8'), filename))
            checked_count += 1
            current_checksum = self._get_file_md5(file_path)
            if current_checksum == stored_checksum:
                verified_count += 1
            else:
                failed_count += 1
                self.logger.error('[FAILED] %s [%s => %s]',
                                  file_path.decode('utf8'),
                                  current_checksum.decode('utf8'),
                                  stored_checksum.decode('utf8'))

        # Use tuples in a list instead of a dictionary to make the stats output
        # ordered
        stats = list()
        stats.extend([('Files checked', checked_count)])
        stats.extend([('Successful verifications', verified_count)])
        stats.extend([('Failed verifications', failed_count)])
        self._display_verification_stats(stats)

        if failed_count != 0:
            self.logger.error('Backup verification failed!')
        else:
            self.status = 'Backup verification completed successfully!'
            self.logger.info(self.status)

        if backup == '_current_':
            self._write_timestamp(self.last_verification_file)

        self.error = False

    def _display_verification_stats(self, stats):
        label_width = 26
        self.logger.info('')

        for line in stats:
            self.logger.info('{0}: {1}'.format(line[0].ljust(label_width),
                             line[1]))

        self.logger.info('')

    def _configure_rsync(self, dest_dir):
        rsync = self.config.get('rsync', 'pathname', fallback='rsync')
        command = [rsync, '-avihh', '--stats', '--out-format=%i %C %n%L']
        command.extend(self.config.get('rsync', 'additional_options').split())

        if self.test:
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
            self.logger.info('Incomplete backup found in %s. Resuming...',
                             incomplete_backup)
            command.append('--delete-excluded')
        else:
            if not self.test:
                self._create_dir(dest_dir)

        command.extend([source, dest_dir])
        return command

    def backup(self):
        self.status = 'Backup failed!'
        self.error = True

        dest_dir = os.path.join(self.backups_dir,
                                'incomplete', 'backup')
        rsync_command = self._configure_rsync(dest_dir)
        self.logger.info('Starting backup labeled \"%s\" to %s',
                         self.config.get('general', 'label'), dest_dir)
        self.logger.info('Commmand: %s',
                         ' '.join(element for element in rsync_command))
        rsync_checksums = self._run_rsync(rsync_command)
        checksums = self._get_checksums(bytes(dest_dir, 'utf8'), rsync_checksums)
        checksum_file = os.path.join(os.path.dirname(dest_dir),
                                     self.checksum_file)
        self._write_checksum_file(checksum_file, checksums)

        # Rename incomplete backup to current and enforce retention
        current_backup = os.path.join(self.backups_dir,
                                      'current_%s' % self.timestamp)

        if not self.test:
            move(os.path.dirname(dest_dir), current_backup)

        self._create_interval_backups(current_backup)
        self._remove_old_backups()
        self._remove_old_logs()

        if self.test:
            self.status = 'Dry run completed successfully!'
        else:
            self.status = 'Backup completed successfully!'

        self.logger.info(self.status)
        self.error = False

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

            if self.test:
                self.logger.info('Creating %s (DRY RUN)', interval_backup)
            else:
                self.logger.info('Creating %s', interval_backup)

                # Use cp instead of copytree because of performance reasons
                #copytree(current_backup, interval_backup, copy_function=os.link)
                subprocess.check_call([
                    'cp', '-al', current_backup, interval_backup
                ])

    def _remove_old_backups(self):
        self.logger.info('Removing old backups...')
        for interval in self.intervals:
            old_backups = [i for i in self._get_backups(interval)]
            old_backups.sort(reverse=True)
            for old_backup in old_backups[
                    self.intervals[interval]['retention']:]:
                if self.test:
                    self.logger.info('Removing %s (DRY RUN)', old_backup)
                else:
                    self.logger.info('Removing %s', old_backup)

                    # Use rm instead of rmtree because of performance reasons
                    #rmtree(old_backup)
                    subprocess.check_call(['rm', '-rf', old_backup])

    def _remove_old_logs(self):
        retention = self.config.getint(
            'retention', 'logs',
            fallback=self.global_config.getint('retention', 'logs'))
        if retention < 1:
            return

        self.logger.info('Removing backup logs older than %d days...',
                         retention)
        old_logs = [i for i in self._get_logs()]
        old_logs.sort(reverse=True)
        for old_log in old_logs:
            if old_log == self.log_file:
                continue

            log_datetime = self._get_log_file_datetime(old_log)
            if (datetime.now() - log_datetime).days > retention:
                if self.test:
                    self.logger.info('Removing %s (DRY RUN)', old_log)
                else:
                    self.logger.info('Removing %s', old_log)
                    os.unlink(old_log)

    def _get_checksums(self, backup_dir, rsync_checksums):
        self.logger.info('Getting checksums for backup files...')
        checksums = list()
        previous_checksum_file = None
        latest_backup = self._get_latest_backup()

        if latest_backup:
            previous_checksum_file = self._get_checksum_file(latest_backup)

        path_prefix_len = len(backup_dir + b'/')
        need_checksum = {
            filename[path_prefix_len:] for filename in
            self._get_files(backup_dir)
        }

        # Add rsync checksums to checksums and remove those files from 
        # from the set of files needing checksum
        self.logger.info('Using %d checksums from rsync', len(rsync_checksums))
        checksums.extend(rsync_checksums)
        need_checksum.difference_update(
            {filename for filename, _ in rsync_checksums})

        if previous_checksum_file:
            # Add existing checksums from the previous backup if the file
            # still exists in need_checksum
            self.logger.info('Reusing unchanged checksums from %s',
                             previous_checksum_file)

            for filename, checksum in self._parse_checksum_file(
                    previous_checksum_file):
                if filename in need_checksum:
                    checksums.append((filename, checksum))
                    need_checksum.discard(filename)

        # Calculate checksums for the rest of the files. There are typically
        # only files left if this is a resumed backup and these files were 
        # transferred in the incomplete backup.
        self.logger.info('Calculating checksum for %d additional files',
                         len(need_checksum))
        need_checksum.difference_update(
            {filename for filename, _ in checksums})

        for filename in need_checksum:
            file_path = os.path.join(backup_dir, filename)
            checksum = self._get_file_md5(file_path)
            checksums.append((filename, checksum))

        return checksums

    def _get_new_logs(self, last_report):
        logs_to_report = list()

        for log_file in sorted(self._get_logs(), reverse=True):
            log_file_datetime = self._get_log_file_datetime(log_file)

            if log_file == self.log_file:
                logs_to_report.extend([(self.status, log_file)])
                continue

            if log_file_datetime > last_report:
                logs_to_report.extend([(
                    self._get_end_status(log_file),
                    log_file)])
            else:
                break

        return sorted(
            logs_to_report,
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

    def _get_incomplete_backup(self):
        path = os.path.join(self.backups_dir, 'incomplete')

        if os.path.isdir(path):
            return path

    def _migrate_backups(self):
        pattern = re.compile(r'^.+_[0-9-]{17}$')

        for entry in scandir.scandir(self.backup_root):
            if pattern.match(entry.name):
                move(entry.path, os.path.join(self.backups_dir, entry.name))

        self.migrated=True

    def _get_backups(self, backup_type):
        if not self.migrated:
            # Migrate backups if using old directory structure
            self._migrate_backups()

        pattern = re.compile(r'^%s_[0-9-]{17}$' % backup_type)

        for entry in scandir.scandir(self.backups_dir):
            if pattern.match(entry.name):
                yield entry.path

    def _get_logs(self):
        pattern = re.compile(r'^[0-9-]{17}.log$')

        for entry in scandir.scandir(self.log_dir):
            if pattern.match(entry.name):
                yield entry.path

    def _get_latest_backup(self):
        try:
            backup = os.path.join(
                sorted(self._get_backups('current'), reverse=True)[0],
                'backup')
        except IndexError:
            backup = None

        return backup

    def _get_backup_dir(self, backup):
        if os.path.split(backup)[0]:
            raise BackupException('You must specify the folder name of the '
                'backup, not a path')

        backup_dir = os.path.join(self.backups_dir, backup, 'backup')

        if not os.path.isdir(backup_dir):
            backup_dir = None

        return backup_dir

    def _get_checksum_file(self, backup):
        filename = None
        checksum_file = os.path.join(
            os.path.dirname(backup), self.checksum_file)
        checksum_file_legacy = os.path.join(
            os.path.dirname(backup), self.checksum_file_legacy)

        if os.path.exists(checksum_file):
            filename = checksum_file
        elif os.path.exists(checksum_file_legacy):
            filename = checksum_file_legacy

        return filename

    def _send_mail(self, status, logs):
        summary = ''
        for end_status, log_file in logs:
            link_to_logs = self.config.getboolean(
                'reporting', 'link_to_logs',
                fallback=self.global_config.getboolean('reporting',
                                                       'link_to_logs'))
            if link_to_logs:
                base_url = self.global_config.get('reporting', 'base_url')
                url = '%s/%s' % (
                    base_url.rstrip('/'),
                    os.path.relpath(
                        log_file,
                            self.global_config.get('general', 'backup_root')))
                summary = '%s%s: %s [ %s ]\n' % (
                    summary, os.path.splitext(os.path.basename(log_file))[0],
                    end_status, url)
            else:
                summary = '%s%s: %s\n' % (
                    summary, os.path.splitext(os.path.basename(log_file))[0],
                    end_status)

        msgtext = """\
%s: %s

Label: %s
Job:   %s


Summary
=======

%s
""" % (
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'), status,
            self.config.get('general', 'label'), self.timestamp,
            summary)

        msg = MIMEText(msgtext, 'plain')
        msg['Subject'] = '%s [%s: %s]' % (
            status, self.config.get('general', 'label'), self.timestamp)
        msg['From'] = self.global_config.get('reporting', 'from_addr')
        msg['To'] = ','.join(addr for addr in self.to_addrs)

        with smtplib.SMTP(
                self.global_config.get('reporting', 'smtp_server')) as sender:
            sender.sendmail(self.global_config.get('reporting', 'from_addr'),
                            self.to_addrs, msg.as_string())

    def report_status(self):
        if self.to_addrs == set(['']):
            self.logger.info('Mail reporting is disabled. Set "to_addrs" in the '
                             'configuration file to enable')
            return

        last_report_file = os.path.join(self.cache_dir, 'last_report')
        last_report = self._get_timestamp(last_report_file)
        interval = self.config.getint(
            'reporting', 'report_interval',
            fallback=self.global_config.getint('reporting', 'report_interval'))

        if self.error:
            self._send_mail(
                self.status, [(self.status, self.log_file)])
        elif not last_report:
            self._send_mail(
                self.status, [(self.status, self.log_file)])
            self._write_timestamp(last_report_file)
        elif ((datetime.now() - last_report).days > interval):
            logs = self._get_new_logs(last_report)
            status = ('%d day backup report' % interval)
            self._send_mail(status, logs)
            self._write_timestamp(last_report_file)
