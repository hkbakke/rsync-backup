#!/usr/bin/env python3

import argparse
import logging
import os
import fnmatch
import sys
from multiprocessing import Pool
import signal
import rsyncbackup

logger = logging.getLogger()


def init_backup(config_name, test, verify):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    try:
        with rsyncbackup.RsyncBackup(config_name, test) as backup:
            if verify:
                backup.verify(verify)
            else:
                backup.backup()
                backup.schedule_verification()
    except KeyboardInterrupt:
        sys.exit(2)


def get_all_configs():
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    conf_dir = os.path.join(script_dir, 'conf.d')             

    for conf in os.listdir(conf_dir):
        if fnmatch.fnmatch(conf, '*.conf'):
            yield os.path.splitext(conf)[0]


def main():
    parser = argparse.ArgumentParser(
        description='Rsync based backup with checksumming and reporting.')

    me_group = parser.add_mutually_exclusive_group(required=True)
    me_group.add_argument('-a', '--backup-all',
                          help='Run all configured backups.',
                          action='store_true')
    me_group.add_argument('-c', '--config-name',
                          help='Select specific backup configuration.')
    parser.add_argument('-p', '--processes', metavar='N', type=int,
                        help='Number of backups to run in parallel.')
    parser.add_argument('-q', '--quiet', help='Suppress output from script.',
                        action='store_true')
    parser.add_argument('-i', '--verify', metavar='BACKUP', nargs='?',
                        const='_current_',
                        help='Verify the integrity of the selected backup. If '
                             'no BACKUP is given the current backup is '
                             'selected.')
    parser.add_argument('-t', '--test',
                        help='Dry run backup. Only logs will be written.',
                        action='store_true')
    parser.add_argument('-l', '--log-level',
                        choices=[
                            'CRITICAL',
                            'ERROR',
                            'WARNING',
                            'INFO',
                            'DEBUG'
                        ],
                        default='DEBUG',
                        help='Set log level for console output.')
    args = parser.parse_args()

    if not args.quiet:
        std_format = logging.Formatter('[%(name)s] [%(levelname)s] %(message)s')

        ch = logging.StreamHandler()
        ch.setFormatter(std_format)
        ch.setLevel(args.log_level)
        logger.addHandler(ch)

    if args.backup_all:
        workers = args.processes if args.processes else 2

        try:
            with Pool(processes=workers) as pool:
                for conf in get_all_configs():
                    pool.apply_async(init_backup,
                                     args=(conf, args.test, args.verify))
                pool.close()
                pool.join()
        except KeyboardInterrupt:
            sys.exit(2)
    elif args.config_name:
        init_backup(args.config_name, args.test, args.verify)


if __name__ == '__main__':
    main()
