import configparser
import logging
import os
import sys
import hashlib
import subprocess
import re
import gzip
from datetime import datetime
import shutil
import smtplib
from email.mime.text import MIMEText
from functools import partial
from operator import attrgetter

try:
    from os import scandir as scandir
except ImportError:
    from scandir import scandir as scandir


class BackupException(Exception):
    pass


class Backup(object):
    def __init__(self, path):
        self.path = None
        self.name = None
        self.timestamp = None
        self.interval = None
        self.backup_dir = None
        self._checksum_file = None
        self._parse_path(path)

    @property
    def checksums(self):
        checksum_file, version = self.checksum_file

        if checksum_file:
            if version == 2:
                with gzip.open(checksum_file, 'rb') as f:
                    for line in f:
                        checksum, filename = line.split(None, 1)
                        filename = filename.strip()

                        yield (filename, checksum)
            elif version == 1:
                with open(checksum_file, 'rb') as f:
                    for line in f:
                        checksum, filename = line.split(None, 1)
                        filename = filename.strip()

                        # Remain compatible with old checksum files
                        if filename.startswith(b'./'):
                            filename = filename[len(b'./'):]

                        yield (filename, checksum)

    @checksums.setter
    def checksums(self, checksums):
        with gzip.open(self._checksum_file, 'wb') as f:
            for filename, checksum in checksums:
                f.write(checksum + b'  ' + filename + b'\n')

    @property
    def checksum_file(self):
        checksum_file_legacy = os.path.join(self.path, 'checksums.md5')
        filename = None
        version = None

        if os.path.exists(self._checksum_file):
            filename = self._checksum_file
            version = 2
        elif os.path.exists(checksum_file_legacy):
            filename = checksum_file_legacy
            version = 1

        return (filename, version)

    @property
    def files(self):
        return self._get_files()

    def _get_files(self, path=None):
        if path is None:
            path = bytes(self.backup_dir, 'utf8')

        for entry in scandir(path):
            if entry.is_file(follow_symlinks=False):
                yield entry.path
            elif entry.is_dir(follow_symlinks=False):
                for dir_file in self._get_files(entry.path):
                    yield dir_file

    @property
    def datetime(self):
        return datetime.strptime(self.timestamp, '%Y-%m-%d-%H%M%S')

    def _parse_path(self, path):
        name = os.path.basename(path)
        pattern = re.compile(r'^(.+)_([0-9-]{17})$')
        m = pattern.match(name)
        timestamp = m.group(2)
        interval = m.group(1)

        self.path = path
        self.name = name
        self.timestamp = timestamp
        self.interval = interval
        self.backup_dir = os.path.join(self.path, 'backup')
        self._checksum_file = os.path.join(self.path, 'checksums.gz')

    @staticmethod
    def get_checksum(file_path):
        """
        Return bytes instead of a string as bytes is used in all other checksum
        file operations as filenames are bytes without encoding in Linux.
        """
        md5 = hashlib.md5()
        chunksize = 128*512
        with open(file_path, 'rb') as f:
            for chunk in iter(partial(f.read, chunksize), b''):
                md5.update(chunk)
        return bytes(md5.hexdigest(), 'utf8')

    def verify(self):
        files = {f for f in self.files}

        for filename, checksum in self.checksums:
            file_path = os.path.join(bytes(self.backup_dir, 'utf8'), filename)
            current_checksum = self.get_checksum(file_path)
            files.discard(file_path)
            verified = False

            if current_checksum == checksum:
                verified = True

            yield (file_path, verified)

        for file_path in files:
            yield (file_path, None)

    def remove(self):
        subprocess.check_call(['rm', '-rf', self.path])

    def move(self, new_path):
        shutil.move(self.path, new_path)
        self._parse_path(new_path)


class RsyncBackup(object):
    def __init__(self, config_name, test=False):
        self.logger = logging.getLogger('%s.%s' % (__name__, config_name))
        self.logger.setLevel(logging.DEBUG)

        self.error = True
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
        self.umask = int(self.global_config.get('general', 'umask',
                                                fallback='0o077'), 8)
        os.umask(self.umask)

        # Configure backup intervals
        self.intervals = {
            'snapshot': {
                'retention': self.config.getint(
                    'retention', 'snapshot',
                    fallback=self.global_config.getint('retention', 'snapshot')),
            },
            'daily': {
                'retention': self.config.getint(
                    'retention', 'daily',
                    fallback=self.global_config.getint('retention', 'daily')),
            },
            'monthly': {
                'retention': self.config.getint(
                    'retention', 'monthly',
                    fallback=self.global_config.getint('retention', 'monthly')),
            },
            'yearly': {
                'retention': self.config.getint(
                    'retention', 'yearly',
                    fallback=self.global_config.getint('retention', 'yearly')),
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
                if line.startswith(b'>f'):
                    rsync_update_info = line.split(b' ', 2)
                    file_checksum = rsync_update_info[1]
                    file_path = rsync_update_info[2]
                    checksums.append((file_path, file_checksum))

        exit_code = p.returncode
        if exit_code != 0:
            raise BackupException(
                'Rsync returned non-zero exit code [ %s ]' % exit_code)

        return checksums

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
            self.logger.debug('Updating timestamp in %s (DRY RUN)', file_path)
            return

        self.logger.debug('Updating timestamp in %s', file_path)

        with open(file_path, 'w') as f:
            f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    def _create_dirs(self):
        dirs = [
            self.backup_root,
            self.backups_dir,
            self.log_dir,
            self.cache_dir
        ]

        for d in dirs:
            self._create_dir(d)

    def _prepare_logging(self):
        fmt = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s')

        # Create file handler for logging to file
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(fmt)
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

        last_verified = self._get_timestamp(self.last_verification_file)

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

    def verify(self, backup_name='_current_'):
        self.status = 'Backup verification failed!'
        self.error = True

        if backup_name == '_current_':
            backup = self._get_latest_backup()
        else:
            backup = self._get_backup_by_name(backup_name)

        if not backup:
            raise BackupException('There is no backup to verify')

        self.logger.info('Initializing checksum verification for %s',
                         backup.path)

        self.logger.info('Starting backup verification...')
        checked_count = 0
        verified_count = 0
        failed_count = 0
        missing_count = 0

        for file_path, verified in backup.verify():
            checked_count += 1

            if verified:
                verified_count += 1
            elif verified is None:
                missing_count += 1
                self.logger.error('[CHECKSUM MISSING] %s', file_path)
            else:
                failed_count += 1
                self.logger.error('[FAILED] %s', file_path)

        # Use tuples in a list instead of a dictionary to make the stats output
        # ordered
        stats = list()
        stats.extend([('Files checked', checked_count)])
        stats.extend([('Successful verifications', verified_count)])
        stats.extend([('Failed verifications', failed_count)])
        stats.extend([('Files missing checksum', missing_count)])
        self._display_verification_stats(stats)

        if failed_count != 0 or missing_count != 0:
            self.logger.error('Backup verification failed!')
        else:
            self.status = 'Backup verification completed successfully!'
            self.logger.info(self.status)

        if backup_name == '_current_':
            self._write_timestamp(self.last_verification_file)

        self.error = False

    def _display_verification_stats(self, stats):
        label_width = 26
        self.logger.info('')

        for line in stats:
            self.logger.info('{0}: {1}'.format(line[0].ljust(label_width),
                             line[1]))

        self.logger.info('')

    def _get_changed_files(self, old_backup, new_backup):
        changed_files = set()

        rsync = self.config.get('rsync', 'pathname', fallback='rsync')
        rsync_command = [
            rsync,
            '-rtvi',
            '--dry-run',
            '--out-format=%i %n%L',
            old_backup.backup_dir + os.sep,
            new_backup.backup_dir + os.sep
        ]

        p = subprocess.Popen(rsync_command, shell=False,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        while p.poll() is None:
            for line in iter(p.stdout.readline, b''):
                line = line.strip()

                if line.startswith(b'>f'):
                    rsynced_file = line.split(b' ', 1)
                    changed_files.add(rsynced_file[1])

        exit_code = p.returncode
        if exit_code != 0:
            raise BackupException(
                'Rsync returned non-zero exit code [ %s ]' % exit_code)

        return changed_files

    def _configure_rsync(self, backup):
        rsync = self.config.get('rsync', 'pathname', fallback='rsync')
        command = [
            rsync,
            '-avihh',
            '--stats',
            '--out-format=%i %C %n%L',
            '--delete-excluded'
        ]
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
            command.append('--link-dest=%s' %
                           previous_backup.backup_dir)

        if not self.test:
            self._create_dir(backup.backup_dir)

        command.extend([source, backup.backup_dir])
        return command

    def backup(self):
        self.status = 'Backup failed!'
        self.error = True

        incomplete_backup = self._get_incomplete_backup()
        new_backup_dir = os.path.join(self.backups_dir,
                                      'incomplete_%s' % self.timestamp)

        if incomplete_backup:
            self.logger.info('Incomplete backup found in %s. Resuming...',
                             incomplete_backup.path)
            backup = incomplete_backup
            backup.move(new_backup_dir)
        else:
            backup = Backup(new_backup_dir)

        self.logger.info('Starting backup labeled \"%s\" to %s',
                         self.config.get('general', 'label'),
                         backup.backup_dir)
        rsync_command = self._configure_rsync(backup)
        self.logger.debug('Command: %s',
                          ' '.join(element for element in rsync_command))
        rsync_checksums = self._run_rsync(rsync_command)

        if not self.test:
            changed_files = set()

            if incomplete_backup:
                previous_backup = self._get_latest_backup()

                if previous_backup:
                    changed_files = self._get_changed_files(previous_backup,
                                                            backup)

            checksums = self._get_checksums(backup, rsync_checksums,
                                            changed_files)
            backup.checksums = checksums
            self.logger.info('Added %d md5 checksums to %s', len(checksums),
                             backup.checksum_file[0])

        if not self.test:
            backup.move(os.path.join(self.backups_dir,
                                     'snapshot_%s' % self.timestamp))

        self._create_interval_backups(backup)
        self._remove_old_backups()
        self._remove_old_logs()

        if self.test:
            self.status = 'Dry run completed successfully!'
        else:
            self.status = 'Backup completed successfully!'

        self.logger.info(self.status)
        self.error = False

    def _create_interval_backups(self, backup):
        now = datetime.now()
        skip_create = set()

        for interval_backup in self._get_backups():
            interval = interval_backup.interval
            backup_date = interval_backup.datetime

            if interval == 'yearly':
                if backup_date.year == now.year:
                    skip_create.add(interval)
            elif interval == 'monthly':
                if (backup_date.year == now.year and
                        backup_date.month == now.month):
                    skip_create.add(interval)
            elif interval == 'daily':
                if (backup_date.year == now.year and
                        backup_date.month == now.month and
                        backup_date.day == now.day):
                    skip_create.add(interval)

        for interval in self.intervals:
            if interval == 'snapshot':
                continue

            if interval in skip_create:
                continue

            if self.intervals[interval]['retention'] < 1:
                continue

            path = os.path.join(self.backups_dir,
                                '%s_%s' % (interval, backup.timestamp))

            if self.test:
                self.logger.info('Creating %s (DRY RUN)', path)
            else:
                self.logger.info('Creating %s', path)

                # Use cp instead of copytree because of performance reasons
                #copytree(backup.path, path, copy_function=os.link)
                subprocess.check_call([
                    'cp', '-al', backup.path, path
                ])

    def _remove_old_backups(self):
        self.logger.info('Removing old backups...')
        to_delete = []
        now = datetime.now()
        snapshots = []

        for backup in self._get_backups():
            interval = backup.interval

            if interval not in self.intervals:
                to_delete.append(backup)
                continue
            elif interval == 'snapshot':
                snapshots.append(backup)
                continue
            elif interval == 'daily':
                max_age = self.intervals[interval]['retention']
            elif interval == 'monthly':
                max_age = self.intervals[interval]['retention'] * 365.25 / 12
            elif interval == 'yearly':
                max_age = self.intervals[interval]['retention'] * 365.25

            if (now - backup.datetime).days >= max_age:
                to_delete.append(backup)

        # Use counts, not days, to enforce retention for snapshots
        snapshots_sorted = sorted(snapshots, key=attrgetter('timestamp'),
                                  reverse=True)
        for backup in snapshots_sorted[self.intervals['snapshot']['retention']:]:
            to_delete.append(backup)

        for backup in to_delete:
            if self.test:
                self.logger.debug('Removing %s (DRY RUN)', backup.path)
            else:
                self.logger.debug('Removing %s', backup.path)
                backup.remove()

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
                    self.logger.debug('Removing %s (DRY RUN)', old_log)
                else:
                    self.logger.debug('Removing %s', old_log)
                    os.unlink(old_log)

    def _get_checksums(self, backup, rsync_checksums, changed_files=None):
        self.logger.info('Getting checksums for backup files...')
        checksums = list()

        # Add all files in backup to a set
        path_prefix_len = len(bytes('%s/' % backup.backup_dir, 'utf8'))
        need_checksum = {f[path_prefix_len:] for f in backup.files}

        # Add rsync checksums to checksums
        self.logger.debug('Using %d checksums from rsync', len(rsync_checksums))
        checksums.extend(rsync_checksums)
        need_checksum.difference_update({f[0] for f in rsync_checksums})

        # Get existing checksummed files from the previous backup, but skip
        # adding checksums for files we know have been changed
        latest_backup = self._get_latest_backup()
        reused_checksums = 0

        for filename, checksum in latest_backup.checksums:
            if filename in need_checksum:
                if filename in changed_files:
                    continue

                checksums.append((filename, checksum))
                need_checksum.discard(filename)
                reused_checksums += 1

        if reused_checksums > 0:
            self.logger.debug('Reused %d unchanged checksums from %s',
                              reused_checksums, latest_backup.checksum_file[0])

        # Calculate checksums for the rest of the files. There are typically
        # only files left if this is a resumed backup and these files were 
        # transferred in a incomplete backup.
        self.logger.debug('Calculating checksum for %d additional files',
                         len(need_checksum))

        for filename in need_checksum:
            file_path = os.path.join(bytes(backup.backup_dir, 'utf8'), filename)
            checksum = backup.get_checksum(file_path)
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
        pattern = re.compile(r'^incomplete_[0-9-]{17}$')

        for backup in self._get_backups():
            if pattern.match(backup.name):
                return backup

    def _get_backups(self):
        pattern = re.compile(r'^.+_[0-9-]{17}$')

        for entry in scandir(self.backups_dir):
            if pattern.match(entry.name):
                yield Backup(entry.path)

    def _get_logs(self):
        pattern = re.compile(r'^[0-9-]{17}.log$')

        for entry in scandir(self.log_dir):
            if pattern.match(entry.name):
                yield entry.path

    def _get_latest_backup(self):
        backup = None

        for backup in sorted(self._get_backups(), key=attrgetter('timestamp'),
                             reverse=True):
            if backup.interval != 'incomplete':
                return backup

        return backup

    def _get_backup_by_name(self, backup_name):
        if os.path.split(backup_name)[0]:
            raise BackupException('You must specify the folder name of the '
                'backup, not a path')

        path = os.path.join(self.backups_dir, backup_name)
        backup = Backup(path)

        if not os.path.isdir(backup.backup_dir):
            backup = None

        return backup

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
