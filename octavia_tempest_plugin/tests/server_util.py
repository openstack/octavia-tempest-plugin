# Copyright 2017 Catalyst IT Ltd
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
import pkg_resources
import random
import shlex
import string
import subprocess
import tempfile
import time

from oslo_log import log as logging
from oslo_utils import excutils
from tempest import config
from tempest.lib.common import fixed_network
from tempest.lib.common import rest_client
from tempest.lib.common.utils.linux import remote_client
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)

SERVER_BINARY = pkg_resources.resource_filename(
    'octavia_tempest_plugin.contrib.httpd', 'httpd.bin')


class BuildErrorException(exceptions.TempestException):
    message = "Server %(server_id)s failed to build and is in ERROR status"


def _get_task_state(body):
    return body.get('OS-EXT-STS:task_state', None)


def wait_for_server_status(client, server_id, status, ready_wait=True,
                           extra_timeout=0, raise_on_error=True):
    """Waits for a server to reach a given status."""

    # NOTE(afazekas): UNKNOWN status possible on ERROR
    # or in a very early stage.
    body = client.show_server(server_id)['server']
    old_status = server_status = body['status']
    old_task_state = task_state = _get_task_state(body)
    start_time = int(time.time())
    timeout = client.build_timeout + extra_timeout
    while True:
        # NOTE(afazekas): Now the BUILD status only reached
        # between the UNKNOWN->ACTIVE transition.
        # TODO(afazekas): enumerate and validate the stable status set
        if status == 'BUILD' and server_status != 'UNKNOWN':
            return
        if server_status == status:
            if ready_wait:
                if status == 'BUILD':
                    return
                # NOTE(afazekas): The instance is in "ready for action state"
                # when no task in progress
                if task_state is None:
                    # without state api extension 3 sec usually enough
                    time.sleep(CONF.compute.ready_wait)
                    return
            else:
                return

        time.sleep(client.build_interval)
        body = client.show_server(server_id)['server']
        server_status = body['status']
        task_state = _get_task_state(body)
        if (server_status != old_status) or (task_state != old_task_state):
            LOG.info('State transition "%s" ==> "%s" after %d second wait',
                     '/'.join((old_status, str(old_task_state))),
                     '/'.join((server_status, str(task_state))),
                     time.time() - start_time)
        if (server_status == 'ERROR') and raise_on_error:
            if 'fault' in body:
                raise BuildErrorException(body['fault'],
                                          server_id=server_id)
            else:
                raise BuildErrorException(server_id=server_id)

        timed_out = int(time.time()) - start_time >= timeout

        if timed_out:
            expected_task_state = 'None' if ready_wait else 'n/a'
            message = ('Server %(server_id)s failed to reach %(status)s '
                       'status and task state "%(expected_task_state)s" '
                       'within the required time (%(timeout)s s).' %
                       {'server_id': server_id,
                        'status': status,
                        'expected_task_state': expected_task_state,
                        'timeout': timeout})
            message += ' Current status: %s.' % server_status
            message += ' Current task state: %s.' % task_state
            caller = test_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            raise exceptions.TimeoutException(message)
        old_status = server_status
        old_task_state = task_state


def wait_for_server_termination(client, server_id, ignore_error=False):
    """Waits for server to reach termination."""
    try:
        body = client.show_server(server_id)['server']
    except exceptions.NotFound:
        return
    old_status = body['status']
    old_task_state = _get_task_state(body)
    start_time = int(time.time())
    while True:
        time.sleep(client.build_interval)
        try:
            body = client.show_server(server_id)['server']
        except exceptions.NotFound:
            return
        server_status = body['status']
        task_state = _get_task_state(body)
        if (server_status != old_status) or (task_state != old_task_state):
            LOG.info('State transition "%s" ==> "%s" after %d second wait',
                     '/'.join((old_status, str(old_task_state))),
                     '/'.join((server_status, str(task_state))),
                     time.time() - start_time)
        if server_status == 'ERROR' and not ignore_error:
            raise exceptions.DeleteErrorException(resource_id=server_id)

        if int(time.time()) - start_time >= client.build_timeout:
            raise exceptions.TimeoutException
        old_status = server_status
        old_task_state = task_state


def create_server(clients, name=None, flavor=None, image_id=None,
                  validatable=False, validation_resources=None,
                  tenant_network=None, wait_until=None, availability_zone=None,
                  **kwargs):
    """Common wrapper utility returning a test server.

    This method is a common wrapper returning a test server that can be
    pingable or sshable.

    :param name: Name of the server to be provisioned. If not defined a random
        string ending with '-instance' will be generated.
    :param flavor: Flavor of the server to be provisioned. If not defined,
        CONF.compute.flavor_ref will be used instead.
    :param image_id: ID of the image to be used to provision the server. If not
        defined, CONF.compute.image_ref will be used instead.
    :param clients: Client manager which provides OpenStack Tempest clients.
    :param validatable: Whether the server will be pingable or sshable.
    :param validation_resources: Resources created for the connection to the
        server. Include a keypair, a security group and an IP.
    :param tenant_network: Tenant network to be used for creating a server.
    :param wait_until: Server status to wait for the server to reach after
        its creation.
    :returns: a tuple
    """
    if name is None:
        r = random.SystemRandom()
        name = "m{}".format("".join(
            [r.choice(string.ascii_uppercase + string.digits)
             for i in range(
                CONF.loadbalancer.random_server_name_length - 1)]
        ))
    if flavor is None:
        flavor = CONF.compute.flavor_ref
    if image_id is None:
        image_id = CONF.compute.image_ref
    if availability_zone is None:
        availability_zone = CONF.loadbalancer.availability_zone

    kwargs = fixed_network.set_networks_kwarg(
        tenant_network, kwargs) or {}

    if availability_zone:
        kwargs.update({'availability_zone': availability_zone})

    if CONF.validation.run_validation and validatable:
        LOG.debug("Provisioning test server with validation resources %s",
                  validation_resources)
        if 'security_groups' in kwargs:
            kwargs['security_groups'].append(
                {'name': validation_resources['security_group']['name']})
        else:
            try:
                kwargs['security_groups'] = [
                    {'name': validation_resources['security_group']['name']}]
            except KeyError:
                LOG.debug("No security group provided.")

        if 'key_name' not in kwargs:
            try:
                kwargs['key_name'] = validation_resources['keypair']['name']
            except KeyError:
                LOG.debug("No key provided.")

        if CONF.validation.connect_method == 'floating':
            if wait_until is None:
                wait_until = 'ACTIVE'

    body = clients.servers_client.create_server(name=name, imageRef=image_id,
                                                flavorRef=flavor,
                                                **kwargs)
    server = rest_client.ResponseBody(body.response, body['server'])

    def _setup_validation_fip():
        if CONF.service_available.neutron:
            ifaces = clients.interfaces_client.list_interfaces(server['id'])
            validation_port = None
            for iface in ifaces['interfaceAttachments']:
                if not tenant_network or (iface['net_id'] ==
                                          tenant_network['id']):
                    validation_port = iface['port_id']
                    break
            if not validation_port:
                # NOTE(artom) This will get caught by the catch-all clause in
                # the wait_until loop below
                raise ValueError('Unable to setup floating IP for validation: '
                                 'port not found on tenant network')
            clients.floating_ips_client.update_floatingip(
                validation_resources['floating_ip']['id'],
                port_id=validation_port)
        else:
            fip_client = clients.compute_floating_ips_client
            fip_client.associate_floating_ip_to_server(
                floating_ip=validation_resources['floating_ip']['ip'],
                server_id=server['id'])

    if wait_until:
        try:
            wait_for_server_status(
                clients.servers_client, server['id'], wait_until)

            # Multiple validatable servers are not supported for now. Their
            # creation will fail with the condition above (l.58).
            if CONF.validation.run_validation and validatable:
                if CONF.validation.connect_method == 'floating':
                    _setup_validation_fip()

        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    clients.servers_client.delete_server(server['id'])
                except Exception:
                    LOG.exception('Deleting server %s failed', server['id'])
                try:
                    wait_for_server_termination(clients.servers_client,
                                                server['id'])
                except Exception:
                    LOG.exception('Server %s failed to delete in time',
                                  server['id'])

    return server


def clear_server(servers_client, id):
    try:
        servers_client.delete_server(id)
    except exceptions.NotFound:
        pass
    wait_for_server_termination(servers_client, id)


def _execute(cmd, cwd=None):
    args = shlex.split(cmd)
    subprocess_args = {'stdout': subprocess.PIPE,
                       'stderr': subprocess.STDOUT,
                       'cwd': cwd}
    proc = subprocess.Popen(args, **subprocess_args)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        LOG.error('Command %s returned with exit status %s, output %s, '
                  'error %s', cmd, proc.returncode, stdout, stderr)
        raise exceptions.CommandFailed(proc.returncode, cmd, stdout, stderr)
    return stdout


def copy_file(floating_ip, private_key, local_file, remote_file):
    """Copy web server script to instance."""
    with tempfile.NamedTemporaryFile() as key:
        key.write(private_key.encode('utf-8'))
        key.flush()
        dest = (
            "%s@%s:%s" %
            (CONF.validation.image_ssh_user, floating_ip, remote_file)
        )
        cmd = ("scp -v -o UserKnownHostsFile=/dev/null "
               "-o StrictHostKeyChecking=no "
               "-i %(key_file)s %(file)s %(dest)s" % {'key_file': key.name,
                                                      'file': local_file,
                                                      'dest': dest})
        return _execute(cmd)


def run_webserver(connect_ip, private_key):
    httpd = "/dev/shm/httpd.bin"

    linux_client = remote_client.RemoteClient(
        connect_ip,
        CONF.validation.image_ssh_user,
        pkey=private_key,
    )
    linux_client.validate_authentication()

    # TODO(kong): We may figure out an elegant way to copy file to instance
    # in future.
    LOG.debug("Copying the webserver binary to the server.")
    copy_file(connect_ip, private_key, SERVER_BINARY, httpd)

    LOG.debug("Starting services on the server.")
    linux_client.exec_command('sudo screen -d -m %s -port 80 -id 1' % httpd)
    linux_client.exec_command('sudo screen -d -m %s -port 81 -id 2' % httpd)
