#!/usr/bin/env python3
# -*- mode: python ; coding: utf-8 -*-

from prometheus_client import start_http_server, Gauge, Enum, Info, Summary, Histogram
from prometheus_client.exposition import make_wsgi_app
from typing import List, Tuple, Dict
from logging import Logger
import time
import os
import sys
import logging
import argparse
import yaml, json
from datetime import datetime
import subprocess
from prometheus_client.core import REGISTRY
from wsgiref.simple_server import make_server

latest_archive_labels = {
    'repository_id': '',
    'repository_name': '',
    'archive_id': '',
    'archive_name': ''
}
repository_labels = {
    'repository_id': '',
    'repository_name': ''
}

borgmatic_config_info                               = Info('borg_borgmatic_config', 'Borgmatic config information')

# respositoy basic values
total_chunks_count                                  = Gauge('borg_repository_total_chunks_count', 'Number of chunks in the repository', list(repository_labels.keys()))
total_chunks_size_bytes                             = Gauge('borg_repository_total_chunks_size_bytes', 'Total size of all chunks', list(repository_labels.keys()))
total_size_bytes                                    = Gauge('borg_repository_total_size_bytes', 'Total uncompressed size of all chunks multiplied with their reference counts', list(repository_labels.keys()))
total_unique_chunks_count                           = Gauge('borg_repository_total_unique_chunks_count', 'Number of unique chunks', list(repository_labels.keys()))
unique_chunks_size_bytes                            = Gauge('borg_repository_unique_chunks_size_bytes', 'Compressed and encrypted size of all chunks', list(repository_labels.keys()))
unique_size_bytes                                   = Gauge('borg_repository_unique_size_bytes', 'Uncompressed size of all chunks', list(repository_labels.keys()))

last_modified_timestamp_seconds                     = Gauge('borg_repository_last_modified_timestamp_seconds', 'Date when the repository was last modified by the Borg client', list(repository_labels.keys()))
encryption_mode                                     = Enum('borg_repository_encryption_mode', 'Textual encryption mode name (same as borg init --encryption names)', list(repository_labels.keys()), states=['none', 'repokey', 'keyfile', 'authenticated', 'keyfile-blake2', 'repokey-blake2', 'authenticated-blake2'])

# repository calculated values
repository_blocked                                  = Enum('borg_repository_blocked', 'Whether the repository is blocked by another borg instance or not', list(repository_labels.keys()), states=['blocked', 'unblocked'])
num_archives                                        = Gauge('borg_repository_num_archives', 'Number of archives in the repository', list(repository_labels.keys()))
all_archives_original_size_difference_bytes         = Gauge('borg_repository_all_archives_original_size_difference_bytes', 'Difference of the original size of the archives in the repository', list(latest_archive_labels.keys()) + ['time'])
all_archives_seconds_per_byte_difference_seconds    = Gauge('borg_repository_all_archives_seconds_per_byte_difference_seconds', 'Difference of the seconds per byte of the archives in the repository', list(latest_archive_labels.keys()) + ['time'])

# latest archive basic values
latest_archive_info                                 = Info('borg_latest_archive_info', 'Information about the latest archive', list(latest_archive_labels.keys()))
latest_archive_duration_seconds                     = Gauge('borg_latest_archive_duration_seconds', 'Seconds it took to create the latest archive', list(latest_archive_labels.keys()))
latest_archive_start_timestamp_seconds              = Gauge('borg_latest_archive_start_timestamp_seconds', 'UNIX timestamp when the creation of the latest archive was initiated', list(latest_archive_labels.keys()))
latest_archive_end_timestamp_seconds                = Gauge('borg_latest_archive_end_timestamp_seconds', 'UNIX timestamp when the creation of the latest archive was completed', list(latest_archive_labels.keys()))
latest_archive_compressed_size_bytes                = Gauge('borg_latest_archive_compressed_size_bytes', 'Size after compression in bytes', list(latest_archive_labels.keys()))
latest_archive_deduplicated_size_bytes              = Gauge('borg_latest_archive_deduplicated_size_bytes', 'Deduplicated size (against the current repository, not when the archive was created) in bytes', list(latest_archive_labels.keys()))
latest_archive_nfiles_count                         = Gauge('borg_latest_archive_nfiles_count', 'Number of regular files in the archive', list(latest_archive_labels.keys()))
latest_archive_original_size_bytes                  = Gauge('borg_latest_archive_original_size_bytes', 'Size of files and metadata before compression in bytes', list(latest_archive_labels.keys()))

# latest archive calculated values
latest_archive_colliding_count                      = Gauge('borg_latest_archive_colliding', 'Count of archives, this archive collided with. A ', list(latest_archive_labels.keys()))

# global logger
# logger = None

# We define a custom collector so we only pull metrics when requested
class BorgCollector:

    def __init__(self, cmd: List[str], repositories: List[str], passphrase: str):
        self.cmd = cmd
        self.repositories = repositories
        self.passphrase = passphrase

    def collect(self):        
        current_time = time.time()
        logger.info("Metrics requested - parsing repositories")
        for repository in self.repositories:
            logger.info(f"Parsing archive list for repository: '{repository}'")
            parse(repository=repository, with_command=self.cmd, and_with_passphrase=self.passphrase)
        
        # This has to stay here, otherwise the metrics will be reset
        return []

def parse(repository: str, with_command: List[str], and_with_passphrase: str) -> None:
    """
    Parse a string containing multiple lines of data and return a list of dictionaries.
    Each line is split into key-value pairs based on whitespace.
    """
    global logger

    env = os.environ.copy()
    env["BORG_PASSPHRASE"] = and_with_passphrase
    env["BORG_EXIT_CODES"] = "modern"

    cmd += [repository]
    logger.debug(f"Executing command: {cmd}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
        info_data = json.loads(result.stdout)
    except Exception as e:
        if result.returncode == 73:
            repository_blocked.labels(**repository_labels).state('blocked')
            return

        logger.error(f"Error executing {cmd}: {e}")
        if result.stderr:
            logger.error(f"Command output: {result.stderr}")
        sys.exit(1)

    # Calulate metrics
    if len(info_data.get('archives')) == 0:
        logger.warning(f"No archives found for repository: {repository}")
        return
    
    latest_archive = info_data.get('archives')[-1]

    #latest_archive_age = datetime.fromisoformat(latest_archive.get('end')).timestamp() - datetime.fromisoformat(latest_archive.get('start')).timestamp()
    latest_archive_start_timestamp = datetime.fromisoformat(latest_archive.get('start')).timestamp()

    latest_archive_colliding_count_value = 0
    for archive in info_data.get('archives'):
        archive_end_time = datetime.fromisoformat(archive.get('end')).timestamp()
        if archive_end_time > latest_archive_start_timestamp:
            latest_archive_colliding_count_value += 1
        else:
            break

    latest_archive_labels['repository_id'] = info_data.get('repository').get('id')
    latest_archive_labels['repository_name'] = info_data.get('repository').get('location')
    latest_archive_labels['archive_id'] = latest_archive.get('id')
    latest_archive_labels['archive_name'] = latest_archive.get('name')
    
    repository_labels['repository_id'] = info_data.get('repository').get('id')
    repository_labels['repository_name'] = info_data.get('repository').get('location')

    # Set metrics
    ## respositoy basic values
    total_chunks_count.labels(**repository_labels).set(info_data.get('cache').get('stats').get('total_chunks'))
    total_chunks_size_bytes.labels(**repository_labels).set(info_data.get('cache').get('stats').get('total_csize'))
    total_size_bytes.labels(**repository_labels).set(info_data.get('cache').get('stats').get('total_size'))
    total_unique_chunks_count.labels(**repository_labels).set(info_data.get('cache').get('stats').get('total_unique_chunks'))
    unique_chunks_size_bytes.labels(**repository_labels).set(info_data.get('cache').get('stats').get('unique_csize'))
    unique_size_bytes.labels(**repository_labels).set(info_data.get('cache').get('stats').get('unique_size'))

    last_modified_timestamp_seconds.labels(**repository_labels).set(datetime.fromisoformat(info_data.get('repository').get('last_modified')).timestamp())
    encryption_mode.labels(**repository_labels).state(info_data.get('encryption').get('mode'))

    ## repository calculated values
    repository_blocked.labels(**repository_labels).state('unblocked')
    num_archives.labels(**repository_labels).set(len(info_data.get('archives')))

    ## latest archive basic values
    latest_archive_duration_seconds.labels(**latest_archive_labels).set(latest_archive.get('duration'))
    latest_archive_start_timestamp_seconds.labels(**latest_archive_labels).set(datetime.fromisoformat(latest_archive.get('start')).timestamp())
    latest_archive_end_timestamp_seconds.labels(**latest_archive_labels).set(datetime.fromisoformat(latest_archive.get('end')).timestamp())
    latest_archive_compressed_size_bytes.labels(**latest_archive_labels).set(latest_archive.get('stats').get('compressed_size'))
    latest_archive_deduplicated_size_bytes.labels(**latest_archive_labels).set(latest_archive.get('stats').get('deduplicated_size'))
    latest_archive_nfiles_count.labels(**latest_archive_labels).set(latest_archive.get('stats').get('nfiles'))
    latest_archive_original_size_bytes.labels(**latest_archive_labels).set(latest_archive.get('stats').get('original_size'))

    latest_archive_colliding_count.labels(**latest_archive_labels).set(latest_archive_colliding_count_value)

    latest_archive_info.labels(**latest_archive_labels).info({
        "duration_seconds": str(latest_archive.get('duration')),
        "start": str(latest_archive.get('start')),
        "end": str(latest_archive.get('end')),
        "compressed_size_bytes": str(latest_archive.get('stats').get('compressed_size')),
        "deduplicated_size_bytes": str(latest_archive.get('stats').get('deduplicated_size')),
        "nfiles_count": str(latest_archive.get('stats').get('nfiles')),
        "original_size_bytes": str(latest_archive.get('stats').get('original_size')),
        "colliding_count": str(latest_archive_colliding_count_value)
    })

    for idx, archive in enumerate(info_data.get('archives')[1:]):
        latest_archive_labels['archive_id'] = archive.get('id')
        latest_archive_labels['archive_name'] = archive.get('name')

        current_seconds_per_byte = archive.get('duration') / archive.get('stats').get('original_size')
        before_seconds_per_byte = info_data.get('archives')[idx-1].get('duration') / info_data.get('archives')[idx-1].get('stats').get('compressed_size')

        all_archives_seconds_per_byte_difference_seconds.labels(**latest_archive_labels, time=archive.get('start')).set(current_seconds_per_byte - before_seconds_per_byte)
        all_archives_original_size_difference_bytes.labels(**latest_archive_labels, time=archive.get('start')).set(archive.get('stats').get('original_size') - info_data.get('archives')[idx-1].get('stats').get('original_size'))

def parse_borgmatic(config: Dict) -> None:
    borgmatic_config_info.info({
        "weekly": str(config.get('keep_weekly', 0)),
        "daily": str(config.get('keep_daily', 0)),
        "hourly": str(config.get('keep_hourly', 0)),
        "monthly": str(config.get('keep_monthly', 0)),
        "yearly": str(config.get('keep_yearly', 0))
    })

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description='Borg Exporter for Prometheus', prog='borg-exporter')
    parser.add_argument('--collector.port', type=int, default=9611, help='Port to run the HTTP server on')
    parser.add_argument('--collector.use_iec', action='store_true', default=False, help='Use IEC (binary) prefixes for sizes. Default is SI (decimal) prefixes.')
    parser.add_argument('--collector.borgmatic.config_path', type=str, default='/etc/borgmatic/config.yaml', help='Path to the Borgmatic config file. Leave empty to ignore borgmatic.')
    parser.add_argument('--collector.borg.repositories', type=str, default=None, nargs='+', 
                        help='Repositories to monitor. Specify multiple repositories separated by spaces. Leave empty to monitor all repositories. Only works if they all have the same passphrase. Setup multiple instances of this exporter if they have different passphrases.')
    parser.add_argument('--collector.borg.passphrase_file', type=str, default=None, help='Path to the file containing the passphrase for the repository. Leave empty to ignore passphrase.')
    parser.add_argument('--collector.borgmatic.use_borg', action='store_true', default=True, help='Use the repositories and passphrase listed in the borgmatic config but use the borg command to access these repositories. Helpful you dont need the borgmatic hooks to access the repositories.')
    parser.add_argument('--collector.log_level', type=str, default='info', choices=["info", "debug", "error", "warning"], help='Log level. Can be one of: debug, info, warning, error, critical. Default is info.')
    args = parser.parse_args()

    # Logging
    logger = logging.getLogger('borg-exporter')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler = logging.StreamHandler()
    if getattr(args, 'collector.log_level') == 'debug':
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
    elif getattr(args, 'collector.log_level') == 'error':
        logger.setLevel(logging.ERROR)
        console_handler.setLevel(logging.ERROR)
    elif getattr(args, 'collector.log_level') == 'warning':
        logger.setLevel(logging.WARNING)
        console_handler.setLevel(logging.WARNING)
    else: 
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.info("Starting Borg Exporter (https://...)")

    collector_borg_repositories = getattr(args, 'collector.borg.repositories')
    collector_borg_passphrase_file = getattr(args, 'collector.borg.passphrase_file')
    collector_borgmatic_config_path = getattr(args, 'collector.borgmatic.config_path')

    # Sanity checks
    if collector_borg_repositories and collector_borg_passphrase_file:
        logger.error("You can only specify one of --collector.borg.repositories or --collector.borg.passphrase_file")
        sys.exit(1)
    if collector_borg_repositories and getattr(args, 'borgmatic.config_path'):
        logger.error("You can only specify one of --collector.borgmatic.config_path or --collector.borg.passphrase_file")
        sys.exit(1)
    if not collector_borgmatic_config_path and not (collector_borg_passphrase_file and collector_borg_repositories):
        logger.error("You have to specify both --collector.borg.repositories and --collector.borg.passphrase_file")
        sys.exit(1)
    if (not os.path.exists(collector_borgmatic_config_path)) and collector_borg_repositories and collector_borg_passphrase_file:
        logger.error(f"Could not find borgmatic config '{borgmatic_config_file_path}', while no repository (--collector.borg.repositories) and passphrase file (--collector.borg.passphrase_file) have been specified.")
        logger.error("Exiting borg-exporter")
        sys.exit(1)

    # Config processing
    if collector_borgmatic_config_path:
        with open(collector_borgmatic_config_path, 'r') as file:
            logger.info(f"Found borgmatic config file: {collector_borgmatic_config_path}")
            try:
                config = yaml.safe_load(file)
            except yaml.YAMLError as e:
                logger.error(f"Error parsing YAML file: {e}")
                sys.exit(1)
        encryption_passphrase = config.get('encryption_passphrase')
        repositories = list(map(lambda i: i.get('path'), config.get('repositories')))
        command = "borgmatic"
        parse_borgmatic(config=config)
    else:
        with open(collector_borg_passphrase_file, 'r') as file:
            try:
                encryption_passphrase = file.read().strip()
            except Exception as e:
                logger.error(f"Error reading passphrase file: {e}")
                sys.exit(1)
        repositories = getattr(args, 'collector.borg.repositories')
        command = "borg"
        with open(getattr(args, 'collector.borg.passphrase_file'), 'r') as file:
            try:
                encryption_passphrase = file.read().strip()
            except Exception as e:
                logger.error(f"Error reading passphrase file: {e}")
                sys.exit(1)
    port = getattr(args, 'collector.port')
    use_iec = getattr(args, 'collector.use_iec')
    if getattr(args, 'collector.borgmatic.use_borg'):
            command = "borg"

    # Start server

    cmd = [command, "info", "-a", "*", "--json"]
    if use_iec:
        cmd.append("--iec")
    logger.info(f"Starting Borg Exporter on port {port}")
    REGISTRY.register(BorgCollector(cmd=cmd, repositories=repositories, passphrase=encryption_passphrase))
    app = make_wsgi_app()
    httpd = make_server('', port, app)
    logger.info(f"Started HTTP server on port {port}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down")
    except Exception as e:
        logger.error(f"Error starting HTTP server: {e}")
        sys.exit(1)