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

logger = logging.getLogger(__name__)


class BackupException(Exception):
    pass


class Backup(object):
    def __init__(self, config_name, test=False):
        self.error = True
        self.status = 'Backup failed!'
        self.pid_created = False
        self.log_params = {
            'backup_config': config_name
        }
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
        self.cache_dir = os.path.normpath(
            os.path.join(self.backup_root, 'cache'))
        self.last_verification_file = os.path.join(
            self.cache_dir, 'last_verification')
        self.checksum_filename = 'checksums.md5'
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
            logger.error(self.status, extra=self.log_params)
        elif exc_type is not None:
            logger.error(exc_value, extra=self.log_params)

        self.cleanup()

    def cleanup(self):
        self.report_status()
        logger.info('END STATUS: %s', self.status, extra=self.log_params)

        if self.pid_created:
            os.remove(self.pidfile)

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
                logger.info(line.decode('utf8'), extra=self.log_params)

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

    def _write_checksum_file(self, checksum_file, checksums):
        if self.test:
            logger.info('Adding %d md5 checksums to %s (DRY RUN)', len(checksums),
                     checksum_file, extra=self.log_params)
            return

        logger.info('Adding %d md5 checksums to %s', len(checksums),
                 checksum_file, extra=self.log_params)
        with open(checksum_file, 'wb') as f:
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
            logger.info('Updating timestamp in %s (DRY RUN)', file_path,
                     extra=self.log_params) 
            return

        logger.info('Updating timestamp in %s', file_path, extra=self.log_params) 
        with open(file_path, 'w') as f:
            f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    def _create_dirs(self):
        self._create_dir(self.backup_root)
        self._create_dir(self.log_dir)
        self._create_dir(self.cache_dir)

    def _prepare_logging(self):
        std_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S%z')
        no_format = logging.Formatter('%(message)s')

        # Create file handler for logging to file
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(std_format)
        logger.addHandler(fh)

    def schedule_verification(self):
        self.error = True

        interval = self.config.getint('general', 'verification_interval',
                                      fallback=self.global_config.getint(
                                          'general', 'verification_interval'))
        if interval == 0:
            logger.warning('Automatic backup verification is disabled. '
                        'This is NOT recommended!', extra=self.log_params)
            return

        last_verified = self._get_timestamp(
            self.last_verification_file)
        if not last_verified:
            self._write_timestamp(self.last_verification_file)
            return

        days_since_verification = (datetime.now() - last_verified).days
        if (days_since_verification > interval):
            logger.info('At least %d days have passed since the backup was last '
                     'verified. Initializing verification...', interval,
                     extra=self.log_params)
            self.verify()

        self.error = False

    def _validate_checksum_file(self, checksum_file, backup_dir):
        if not os.path.isfile(checksum_file):
            raise BackupException('The file %s does not exist' % checksum_file)

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

    def verify(self, backup='_current_'):
        self.status = 'Backup verification failed!'
        self.error = True

        logger.info('Initializing checksum verification for %s',
                 self.backup_root, extra=self.log_params)

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

        logger.info('Selected checksum file: %s', checksum_file,
                 extra=self.log_params)
        self._validate_checksum_file(checksum_file, backup_dir)
        logger.info('Starting backup verification...', extra=self.log_params)
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
                logger.error('[FAILED] %s [%s => %s]',
                                file_path.decode('utf8'),
                                current_checksum.decode('utf8'),
                                stored_checksum.decode('utf8'),
                                extra=self.log_params)

        # Use tuples in a list instead of a dictionary to make the stats output
        # ordered
        stats = list()
        stats.extend([('Files checked', checked_count)])
        stats.extend([('Successful verifications', verified_count)])
        stats.extend([('Failed verifications', failed_count)])
        self._display_verification_stats(stats)

        if failed_count != 0:
            logger.error('Backup verification failed!', extra=self.log_params)
        else:
            self.status = 'Backup verification completed successfully!'
            logger.info(self.status, extra=self.log_params)

        if backup == '_current_':
            self._write_timestamp(self.last_verification_file)

        self.error = False

    def _display_verification_stats(self, stats):
        label_width = 26
        logger.info('', extra=self.log_params)
        for line in stats:
            logger.info('{0}: {1}'.format(line[0].ljust(label_width),
                           line[1]),
                           extra=self.log_params)
        logger.info('', extra=self.log_params)

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
            logger.info('Incomplete backup found in %s. Resuming...',
                     incomplete_backup, extra=self.log_params)

            if self.test:
                dest_dir = incomplete_backup
            else:
                move(incomplete_backup, os.path.dirname(dest_dir))

            command.append('--delete-excluded')
        else:
            if not self.test:
                self._create_dir(dest_dir)

        command.extend([source, dest_dir])
        return command

    def backup(self):
        self.status = 'Backup failed!'
        self.error = True

        dest_dir = os.path.join(
            self.backup_root, 'incomplete_%s' % self.timestamp, 'backup')
        rsync_command = self._configure_rsync(dest_dir)
        logger.info('Starting backup labeled \"%s\" to %s',
                 self.config.get('general', 'label'), dest_dir,
                 extra=self.log_params)
        logger.info('Commmand: %s',
                 ' '.join(element for element in rsync_command),
                 extra=self.log_params)
        rsync_checksums = self._run_rsync(rsync_command)

        checksums = self._get_checksums(dest_dir, rsync_checksums)
        checksum_file = os.path.join(
        os.path.dirname(dest_dir), self.checksum_filename)
        self._write_checksum_file(checksum_file, checksums)

        # Rename incomplete backup to current and enforce retention
        current_backup = os.path.join(
            self.backup_root, 'current_%s' % self.timestamp)

        if not self.test:
            move(os.path.dirname(dest_dir), current_backup)

        self._create_interval_backups(current_backup)
        self._remove_old_backups()
        self._remove_old_logs()

        if self.test:
            self.status = 'Dry run completed successfully!'
        else:
            self.status = 'Backup completed successfully!'

        logger.info(self.status, extra=self.log_params)
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
                logger.info('Creating %s (DRY RUN)', interval_backup,
                         extra=self.log_params)
            else:
                logger.info('Creating %s', interval_backup, extra=self.log_params)
                copytree(
                    current_backup, interval_backup, copy_function=os.link)

    def _remove_old_backups(self):
        logger.info('Removing old backups...', extra=self.log_params)
        for interval in self.intervals:
            old_backups = [i for i in self._get_backups(interval)]
            old_backups.sort(reverse=True)
            for old_backup in old_backups[
                    self.intervals[interval]['retention']:]:
                if self.test:
                    logger.info('Removing %s (DRY RUN)', old_backup,
                             extra=self.log_params)
                else:
                    logger.info('Removing %s', old_backup, extra=self.log_params)
                    rmtree(old_backup)

    def _remove_old_logs(self):
        retention = self.config.getint(
            'retention', 'logs',
            fallback=self.global_config.getint('retention', 'logs'))
        if retention < 1:
            return

        logger.info('Removing backup logs older than %d days...', retention,
                 extra=self.log_params)
        old_logs = [i for i in self._get_logs()]
        old_logs.sort(reverse=True)
        for old_log in old_logs:
            if old_log == self.log_file:
                continue

            log_datetime = self._get_log_file_datetime(old_log)
            if (datetime.now() - log_datetime).days > retention:
                if self.test:
                    logger.info('Removing %s (DRY RUN)', old_log,
                             extra=self.log_params)
                else:
                    logger.info('Removing %s', old_log, extra=self.log_params)
                    os.unlink(old_log)

    def _get_checksums(self, backup_dir, rsync_checksums):
        backup_dir = bytes(backup_dir, 'utf8')
        current_files = {
            re.sub(re.escape(backup_dir), b'.', filename, 1)
            for filename in self._get_files_recursive(backup_dir)}

        checksums = rsync_checksums
        previous_checksum_file = None
        latest_backup = self._get_latest_backup()

        if latest_backup:
            previous_checksum_file = self._get_checksum_file(latest_backup)

        if previous_checksum_file:
            logger.info('Reusing unchanged checksums from %s',
                     previous_checksum_file, extra=self.log_params)
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
        logger.info('Calculating checksum for %d additional files',
                 len(need_checksum), extra=self.log_params)
        for filename in need_checksum:
            filename_path = os.path.join(backup_dir, filename)
            if os.path.islink(filename_path):
                continue

            if os.path.isfile(filename_path):
                checksum = self._get_file_md5(filename_path)
                checksums.append([filename, checksum])

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
        for backup_path in os.listdir(self.backup_root):
            if re.match(r'^incomplete_[0-9-]{17}$', backup_path):
                return os.path.join(self.backup_root, backup_path)

    def _get_backups(self, backup_type):
        for backup_path in os.listdir(self.backup_root):
            if re.match(r'^%s_[0-9-]{17}$' % backup_type, backup_path):
                yield os.path.join(self.backup_root, backup_path)

    def _get_logs(self):
        for log_file_path in os.listdir(self.log_dir):
            if re.match(r'^[0-9-]{17}.log$', log_file_path):
                yield os.path.join(self.log_dir, log_file_path)

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

        backup_dir = os.path.join(self.backup_root, backup, 'backup')

        if not os.path.isdir(backup_dir):
            backup_dir = None

        return backup_dir

    def _get_checksum_file(self, backup):
        checksum_file = os.path.join(
            os.path.dirname(backup), self.checksum_filename)

        if not os.path.exists(checksum_file):
            checksum_file = None

        return checksum_file

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
            logger.info('Mail reporting is disabled. Set "to_addrs" in the '
                     'configuration file to enable', extra=self.log_params)
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
