#!/usr/bin/env python
"""Database sanitization using Acquia Cloud."""

import acapi
import datetime
import boto3
import logging
import paramiko
import os
import sys
import time
import tempfile
import traceback
import urlparse

from iron_worker import IronWorker
from slacker import Slacker


def db_backup(client, sub, env):
    """
    Creates a new database backup on Acquia Cloud.

    :param client: The Acquia Cloud API client.
    :type client: acapi.
    :param sub: The machine name of the Acquia subscription.
    :type sub: str.
    :param env: The environment.
    :type env: str.
    :return: The new backup object.
    :rtype: Database.
    """

    max_attempts = 3
    attempt = 1
    error = None
    while True:
        try:
            return client.site(sub).environment(env).db(sub).backups().create()
        except Exception as e:
            error = e
            if e.task['logs'].find('Slave too far behind master') != -1 \
                    and attempt <= max_attempts:
                logging.error("Slave too far behind master. Task ID: %s",
                              e.task['id'])
                time.sleep(attempt * 60)
            else:
                raise

    # Let the most recent exception bubble up
    raise error


def db_copy(client, sub, source, target):
    """
    Copies a database from one environment to another.

    :param client: The Acquia Cloud API client.
    :type client: acapi.
    :param sub: The machine name of the Acquia subscription.
    :type sub: str.
    :param source: The source environment.
    :type source: str.
    :param target: The target environment.
    :type target: str.
    :return: The new database object.
    :rtype: Database.
    """

    max_attempts = 3
    attempt = 1
    error = None
    while True:
        try:
            return client.site(sub).environment(source).db(sub).copy(target)
        except Exception as e:
            error = e
            if attempt <= max_attempts and \
                            e.task['logs'].find(
                                'Slave too far behind master') != -1:
                logging.error("Slave too far behind master. Task ID: %s",
                              e.task.id)
                time.sleep(attempt * i)
            else:
                raise

    # Let the most recent exception bubble up
    raise error


def drupal_version(client, site, env, only_major=True):
    """Get the version of Drupal the site is running.

    :param client: Acquia Cloud API client.
    :param site: The site to check.
    :param env: The environment to check.
    :param only_major: Only return the major component of the version of the full string?
    :return: The drupal version.
    """
    out, err = run_drush_command_acquia(client,
                                        site,
                                        env,
                                        'status drupal-version --format=list')
    version = out.strip()
    if only_major:
        return int(version.split('.')[0])

    return version


def get_server(client, site, env, service_type='web'):
    """
    Gets the FQDN of the first online server for an environment.
    """
    servers = client.site(site).environment(env).servers()
    for name in servers:
        server = servers[name].get()
        services = server['services']
        for stype in services:
            if service_type != stype:
                continue

            service = services[stype]
            if not 'status' in service or not 'active' in service:
                return server['fqdn'].encode('ascii', 'ignore')

            if 'online' == service['status'] and 'active' == service['env_status']:
                return server['fqdn'].encode('ascii', 'ignore')


def run_drush_command_acquia(client, sub, env, cmd):
    """Run a drush command on an Acquia server.

    :param client: The Acquia Cloud API Client object.
    :type client: acapi.
    :param sub: The Acquia subscription to run the commands against.
    :type sub: str.
    :param env: The Acquia environment to run the commands against.
    :type env: str.
    :param cmd: The drush command to run.
    :type cmd: str.
    :return: The command output.
    :rtype: tuple
    """

    server = get_server(client, sub, env)
    user = '{sub}.{env}'.format(sub=sub, env=env)
    run = '/usr/local/bin/drush8 --yes @{user} {cmd}'.format(user=user,
                                                             cmd=cmd)
    out, err = run_ssh_command(user, server, run)

    return out, err


def run_ssh_command(username, server, command, strin=None):
    """Run a SSH command on a remote server.

    :param username: The user to use for authentication.
    :type username: str.
    :param server: The server to run the command on.
    :type server: str.
    :param command: The command to execute.
    :type command: str.
    :param strin: String to be supplied to stdin on remote server.
    :type strin: str.
    :return: The output from stdout and stderr as strings.
    :rtype: tuple
    :raises IOError: If command fails.
    """

    logging.info("Running %s as %s on %s", command, username, server)
    buffer_size = 1024
    ssh = ssh_connect(username, server)
    session = ssh.get_transport().open_session()

    session.settimeout(10800)
    session.exec_command(command)

    stdout_data = []
    stderr_data = []

    while not session.exit_status_ready():
        if session.recv_ready():
            stdout_data.append(session.recv(buffer_size))

        if session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(buffer_size))

    exit_status = session.recv_exit_status()

    stdout = "".join(stdout_data)
    stderr = "".join(stderr_data)

    if 0 != exit_status:
        logging.error("Command failed. Exit code: %d\nstderr:\n%s\nstdout:%s",
                      exit_status, stderr, stdout)
        raise IOError('SSH command failed', stderr.split("\n"), exit_status)

    ssh.close()

    logging.debug("stderr:\n%s\nstdout:%s", stderr, stdout)

    return stdout, stderr


def ssh_connect(username, server):
    """
    Creates a new SSH connection.

    :param username: The user to authenticate as.
    :type username: str.
    :param server: The name of the remote server to connect to.
    :type server: str.
    :rtype: paramiko.SSHClient
    """
    pkey = ssh_get_rsakey()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server, username=username, pkey=pkey)

    return ssh


def ssh_get_rsakey():
    """
    Fetches a paramiko.RSAKey object based on environment variables.

    :return: The RSAKey object if config found in environment variables otherwise None.
    :rtype: None.
    """
    config = IronWorker.config()
    if config:
        if 'SSH_KEY_FILE' not in config:
            raise Exception("SSH public key not found.")

        filename = config['SSH_KEY_FILE']
        password = config['SSH_PASSPHRASE']

        pkey = paramiko.rsakey.RSAKey(filename=filename, password=password)
        logging.info("Loaded SSH private key from %s", filename)
        return pkey

    return None


def sanitize_db(config, client, site, env='prod'):
    """
    Sanitizes a database using the dev9 environment.

    :param config: Configuration dictionary.
    :type config: dict.
    :param client: Acquia Cloud API client instance.
    :type client: acapi.
    :param site: The subscription name of the site.
    :type site: str.
    :param env: The target environment.
    :type env: str.
    :param domain: The FQDN for the site. Only used by WF to determine the correct env.
    :type domain: str.
    :return: The name of the filename as saved in S3.
    :rtype: str.
    """

    sanitize_env = 'dev9'

    logging.info('Backing update database for %s:%s.', site, env)

    ts = datetime.datetime.utcnow().strftime("%s")
    s3_filename = '{site}/{env}-{ts}.sql.gz'.format(site=site, env=env, ts=ts)

    client.site(site).copy_code(env, sanitize_env)
    logging.debug('Code sync completed.')

    # We sync the DB after the code to minimise the time data is unsanitized.
    db_copy(client, site, env, sanitize_env)
    logging.debug('DB sync completed.')

    if drupal_version(client, site, env) == 8:
        run_drush_command_acquia(client, site, sanitize_env, 'rebuild')
    else:
        run_drush_command_acquia(client, site, sanitize_env,
                                 'registry-rebuild')

    run_drush_command_acquia(client, site, sanitize_env, 'sql-sanitize')
    logging.debug('DB Sanitized.')

    (ignored, path) = tempfile.mkstemp()

    backup = db_backup(client, site, sanitize_env)
    backup.download(path)
    backup.delete()

    s3 = boto3.resource('s3')
    s3.Bucket(config['S3_BUCKET']).upload_file(path, s3_filename)
    logging.info('Backup complete.')

    return s3_filename


def main():
    """
    Run the backup.

    :return: None
    """

    logging.StreamHandler(sys.stderr)
    logging.getLogger().setLevel(logging.INFO)

    config = IronWorker.config()

    payload_fp = open(IronWorker.arguments['payload_file'])
    raw_payload = payload_fp.read()
    payload_fp.close()
    payload = dict(urlparse.parse_qsl(raw_payload))

    env_vars = ['ACQUIA_CLOUD_API_USER',
                'ACQUIA_CLOUD_API_TOKEN',
                'AWS_SECRET_ACCESS_KEY',
                'AWS_ACCESS_KEY_ID',
                ]
    for env_var in env_vars:
        os.environ[env_var] = config[env_var]

    (payload['site'], payload['env']) = payload['text'].split(' ', 2)

    success = True
    try:
        client = acapi.Client(cache=None)
        s3_filename = sanitize_db(config,
                                  client,
                                  payload['site'],
                                  payload['env'])
    except Exception:
        success = False
        traceback.print_exc()

    slack = Slacker(config['SLACK_AUTH_TOKEN'])
    if not success:
        task_id = IronWorker.task_id()
        msg = '{site}.{env} dump failed - {tid}'.format(site=payload['site'],
                                                        env=payload['env'],
                                                        tid=task_id)
        slack.chat.post_message(payload['user_id'], msg)
        sys.exit(1)

    s3_params = {'Bucket': config['S3_BUCKET'], 'Key': s3_filename}
    s3_client = boto3.client('s3')
    url = s3_client.generate_presigned_url('get_object',
                                           Params=s3_params,
                                           ExpiresIn=600)

    msg = '{site}.{env} dump - {url}'.format(site=payload['site'],
                                             env=payload['env'],
                                             url=url)
    slack.chat.post_message('@' + payload['user_name'], msg)


if __name__ == '__main__':
    main()
