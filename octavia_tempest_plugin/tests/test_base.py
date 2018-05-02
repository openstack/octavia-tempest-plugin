# Copyright 2018 Rackspace US Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import ipaddress
import pkg_resources
import random
import shlex
import six
import string
import subprocess
import tempfile

from oslo_log import log as logging
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.linux import remote_client
from tempest.lib import exceptions
from tempest import test

from octavia_tempest_plugin import clients
from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import validators
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class LoadBalancerBaseTest(test.BaseTestCase):
    """Base class for load balancer tests."""

    # Setup cls.os_roles_lb_member. cls.os_primary, cls.os_roles_lb_member,
    # and cls.os_roles_lb_admin credentials.
    credentials = ['admin', 'primary',
                   ['lb_member', CONF.load_balancer.member_role],
                   ['lb_member2', CONF.load_balancer.member_role],
                   ['lb_admin', CONF.load_balancer.admin_role]]

    client_manager = clients.ManagerV2

    @classmethod
    def skip_checks(cls):
        """Check if we should skip all of the children tests."""
        super(LoadBalancerBaseTest, cls).skip_checks()

        service_list = {
            'load_balancer': CONF.service_available.load_balancer,
        }

        live_service_list = {
            'compute': CONF.service_available.nova,
            'image': CONF.service_available.glance,
            'neutron': CONF.service_available.neutron
        }

        if not CONF.load_balancer.test_with_noop:
            service_list.update(live_service_list)

        for service, available in service_list.items():
            if not available:
                skip_msg = ("{0} skipped as {1} serivce is not "
                            "available.".format(cls.__name__, service))
                raise cls.skipException(skip_msg)

        # We must be able to reach our VIP and instances
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        """Setup test credentials and network resources."""
        # Do not auto create network resources
        cls.set_network_resources()
        super(LoadBalancerBaseTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """Setup client aliases."""
        super(LoadBalancerBaseTest, cls).setup_clients()
        cls.lb_mem_float_ip_client = cls.os_roles_lb_member.floating_ips_client
        cls.lb_mem_keypairs_client = cls.os_roles_lb_member.keypairs_client
        cls.lb_mem_net_client = cls.os_roles_lb_member.networks_client
        cls.lb_mem_ports_client = cls.os_roles_lb_member.ports_client
        cls.lb_mem_routers_client = cls.os_roles_lb_member.routers_client
        cls.lb_mem_SG_client = cls.os_roles_lb_member.security_groups_client
        cls.lb_mem_SGr_client = (
            cls.os_roles_lb_member.security_group_rules_client)
        cls.lb_mem_servers_client = cls.os_roles_lb_member.servers_client
        cls.lb_mem_subnet_client = cls.os_roles_lb_member.subnets_client
        cls.mem_lb_client = cls.os_roles_lb_member.loadbalancer_client
        cls.mem_listener_client = cls.os_roles_lb_member.listener_client
        cls.mem_pool_client = cls.os_roles_lb_member.pool_client

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(LoadBalancerBaseTest, cls).resource_setup()

        conf_lb = CONF.load_balancer

        if conf_lb.test_subnet_override and not conf_lb.test_network_override:
            raise exceptions.InvalidConfiguration(
                "Configuration value test_network_override must be "
                "specified if test_subnet_override is used.")

        show_subnet = cls.lb_mem_subnet_client.show_subnet
        if CONF.load_balancer.test_with_noop:
            cls.lb_member_vip_net = {'id': uuidutils.generate_uuid()}
            cls.lb_member_vip_subnet = {'id': uuidutils.generate_uuid()}
            cls.lb_member_1_net = {'id': uuidutils.generate_uuid()}
            cls.lb_member_1_subnet = {'id': uuidutils.generate_uuid()}
            cls.lb_member_2_net = {'id': uuidutils.generate_uuid()}
            cls.lb_member_2_subnet = {'id': uuidutils.generate_uuid()}
            if CONF.load_balancer.test_with_ipv6:
                cls.lb_member_vip_ipv6_subnet = {'id':
                                                 uuidutils.generate_uuid()}
                cls.lb_member_1_ipv6_subnet = {'id': uuidutils.generate_uuid()}
                cls.lb_member_2_ipv6_subnet = {'id': uuidutils.generate_uuid()}
            return
        elif CONF.load_balancer.test_network_override:
            if conf_lb.test_subnet_override:
                override_subnet = show_subnet(conf_lb.test_subnet_override)
            else:
                override_subnet = None

            show_net = cls.lb_mem_net_client.show_network
            override_network = show_net(conf_lb.test_network_override)
            override_network = override_network.get('network')

            cls.lb_member_vip_net = override_network
            cls.lb_member_vip_subnet = override_subnet
            cls.lb_member_1_net = override_network
            cls.lb_member_1_subnet = override_subnet
            cls.lb_member_2_net = override_network
            cls.lb_member_2_subnet = override_subnet

            if (CONF.load_balancer.test_with_ipv6 and
                    conf_lb.test_IPv6_subnet_override):
                override_ipv6_subnet = show_subnet(
                    conf_lb.test_IPv6_subnet_override)
                cls.lb_member_vip_ipv6_subnet = override_ipv6_subnet
                cls.lb_member_1_ipv6_subnet = override_ipv6_subnet
                cls.lb_member_2_ipv6_subnet = override_ipv6_subnet
            else:
                cls.lb_member_vip_ipv6_subnet = None
                cls.lb_member_1_ipv6_subnet = None
                cls.lb_member_2_ipv6_subnet = None
        else:
            cls._create_networks()

        LOG.debug('Octavia Setup: lb_member_vip_net = {}'.format(
            cls.lb_member_vip_net[const.ID]))
        if cls.lb_member_vip_subnet:
            LOG.debug('Octavia Setup: lb_member_vip_subnet = {}'.format(
                cls.lb_member_vip_subnet[const.ID]))
        LOG.debug('Octavia Setup: lb_member_1_net = {}'.format(
            cls.lb_member_1_net[const.ID]))
        if cls.lb_member_1_subnet:
            LOG.debug('Octavia Setup: lb_member_1_subnet = {}'.format(
                cls.lb_member_1_subnet[const.ID]))
        LOG.debug('Octavia Setup: lb_member_2_net = {}'.format(
            cls.lb_member_2_net[const.ID]))
        if cls.lb_member_2_subnet:
            LOG.debug('Octavia Setup: lb_member_2_subnet = {}'.format(
                cls.lb_member_2_subnet[const.ID]))
        if cls.lb_member_vip_ipv6_subnet:
            LOG.debug('Octavia Setup: lb_member_vip_ipv6_subnet = {}'.format(
                cls.lb_member_vip_ipv6_subnet[const.ID]))
        if cls.lb_member_1_ipv6_subnet:
            LOG.debug('Octavia Setup: lb_member_1_ipv6_subnet = {}'.format(
                cls.lb_member_1_ipv6_subnet[const.ID]))
        if cls.lb_member_2_ipv6_subnet:
            LOG.debug('Octavia Setup: lb_member_2_ipv6_subnet = {}'.format(
                cls.lb_member_2_ipv6_subnet[const.ID]))

        # If validation is disabled in this cloud, we won't be able to
        # start the webservers, so don't even boot them.
        if not CONF.validation.run_validation:
            return

        # Create a keypair for the webservers
        keypair_name = data_utils.rand_name('lb_member_keypair')
        result = cls.lb_mem_keypairs_client.create_keypair(
            name=keypair_name)
        cls.lb_member_keypair = result['keypair']
        LOG.info('lb_member_keypair: {}'.format(cls.lb_member_keypair))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_keypairs_client.delete_keypair,
            cls.lb_mem_keypairs_client.show_keypair,
            keypair_name)

        if (CONF.load_balancer.enable_security_groups and
                CONF.network_feature_enabled.port_security):
            # Set up the security group for the webservers
            SG_name = data_utils.rand_name('lb_member_SG')
            cls.lb_member_sec_group = (
                cls.lb_mem_SG_client.create_security_group(
                    name=SG_name)['security_group'])
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_SG_client.delete_security_group,
                cls.lb_mem_SG_client.show_security_group,
                cls.lb_member_sec_group['id'])

            # Create a security group rule to allow 80-81 (test webservers)
            SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                direction='ingress',
                security_group_id=cls.lb_member_sec_group['id'],
                protocol='tcp',
                ethertype='IPv4',
                port_range_min=80,
                port_range_max=81)['security_group_rule']
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_SGr_client.delete_security_group_rule,
                cls.lb_mem_SGr_client.show_security_group_rule,
                SGr['id'])
            # Create a security group rule to allow 22 (ssh)
            SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                direction='ingress',
                security_group_id=cls.lb_member_sec_group['id'],
                protocol='tcp',
                ethertype='IPv4',
                port_range_min=22,
                port_range_max=22)['security_group_rule']
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_SGr_client.delete_security_group_rule,
                cls.lb_mem_SGr_client.show_security_group_rule,
                SGr['id'])
            if CONF.load_balancer.test_with_ipv6:
                # Create a security group rule to allow 80-81 (test webservers)
                SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                    direction='ingress',
                    security_group_id=cls.lb_member_sec_group['id'],
                    protocol='tcp',
                    ethertype='IPv6',
                    port_range_min=80,
                    port_range_max=81)['security_group_rule']
                cls.addClassResourceCleanup(
                    waiters.wait_for_not_found,
                    cls.lb_mem_SGr_client.delete_security_group_rule,
                    cls.lb_mem_SGr_client.show_security_group_rule,
                    SGr['id'])
                # Create a security group rule to allow 22 (ssh)
                SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                    direction='ingress',
                    security_group_id=cls.lb_member_sec_group['id'],
                    protocol='tcp',
                    ethertype='IPv6',
                    port_range_min=22,
                    port_range_max=22)['security_group_rule']
                cls.addClassResourceCleanup(
                    waiters.wait_for_not_found,
                    cls.lb_mem_SGr_client.delete_security_group_rule,
                    cls.lb_mem_SGr_client.show_security_group_rule,
                    SGr['id'])

            LOG.info('lb_member_sec_group: {}'.format(cls.lb_member_sec_group))

        # Create webserver 1 instance
        server_details = cls._create_webserver('lb_member_webserver1',
                                               cls.lb_member_1_net)

        cls.lb_member_webserver1 = server_details['server']
        cls.webserver1_ip = server_details.get('ipv4_address')
        cls.webserver1_ipv6 = server_details.get('ipv6_address')
        cls.webserver1_public_ip = server_details['public_ipv4_address']

        LOG.debug('Octavia Setup: lb_member_webserver1 = {}'.format(
            cls.lb_member_webserver1[const.ID]))
        LOG.debug('Octavia Setup: webserver1_ip = {}'.format(
            cls.webserver1_ip))
        LOG.debug('Octavia Setup: webserver1_ipv6 = {}'.format(
            cls.webserver1_ipv6))
        LOG.debug('Octavia Setup: webserver1_public_ip = {}'.format(
            cls.webserver1_public_ip))

        cls._install_start_webserver(cls.webserver1_public_ip,
                                     cls.lb_member_keypair['private_key'], 1)

        # Validate webserver 1
        cls._validate_webserver(cls.webserver1_public_ip, 1)

        # Create webserver 2 instance
        server_details = cls._create_webserver('lb_member_webserver2',
                                               cls.lb_member_2_net)

        cls.lb_member_webserver2 = server_details['server']
        cls.webserver2_ip = server_details.get('ipv4_address')
        cls.webserver2_ipv6 = server_details.get('ipv6_address')
        cls.webserver2_public_ip = server_details['public_ipv4_address']

        LOG.debug('Octavia Setup: lb_member_webserver2 = {}'.format(
            cls.lb_member_webserver2[const.ID]))
        LOG.debug('Octavia Setup: webserver2_ip = {}'.format(
            cls.webserver2_ip))
        LOG.debug('Octavia Setup: webserver2_ipv6 = {}'.format(
            cls.webserver2_ipv6))
        LOG.debug('Octavia Setup: webserver2_public_ip = {}'.format(
            cls.webserver2_public_ip))

        cls._install_start_webserver(cls.webserver2_public_ip,
                                     cls.lb_member_keypair['private_key'], 5)

        # Validate webserver 2
        cls._validate_webserver(cls.webserver2_public_ip, 5)

    @classmethod
    def _install_start_webserver(cls, ip_address, ssh_key, start_id):
        local_file = pkg_resources.resource_filename(
            'octavia_tempest_plugin.contrib.httpd', 'httpd.bin')
        dest_file = '/dev/shm/httpd.bin'

        linux_client = remote_client.RemoteClient(
            ip_address, CONF.validation.image_ssh_user, pkey=ssh_key)
        linux_client.validate_authentication()

        with tempfile.NamedTemporaryFile() as key:
            key.write(ssh_key.encode('utf-8'))
            key.flush()
            cmd = ("scp -v -o UserKnownHostsFile=/dev/null "
                   "-o StrictHostKeyChecking=no "
                   "-o ConnectTimeout={0} -o ConnectionAttempts={1} "
                   "-i {2} {3} {4}@{5}:{6}").format(
                CONF.load_balancer.scp_connection_timeout,
                CONF.load_balancer.scp_connection_attempts,
                key.name, local_file, CONF.validation.image_ssh_user,
                ip_address, dest_file)
            args = shlex.split(cmd)
            subprocess_args = {'stdout': subprocess.PIPE,
                               'stderr': subprocess.STDOUT,
                               'cwd': None}
            proc = subprocess.Popen(args, **subprocess_args)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                raise exceptions.CommandFailed(proc.returncode, cmd,
                                               stdout, stderr)
        linux_client.exec_command('sudo screen -d -m {0} -port 80 '
                                  '-id {1}'.format(dest_file, start_id))
        linux_client.exec_command('sudo screen -d -m {0} -port 81 '
                                  '-id {1}'.format(dest_file, start_id + 1))

    @classmethod
    def _create_networks(cls):
        """Creates networks, subnets, and routers used in tests.

        The following are expected to be defined and available to the tests:
            cls.lb_member_vip_net
            cls.lb_member_vip_subnet
            cls.lb_member_vip_ipv6_subnet (optional)
            cls.lb_member_1_net
            cls.lb_member_1_subnet
            cls.lb_member_1_ipv6_subnet (optional)
            cls.lb_member_2_net
            cls.lb_member_2_subnet
            cls.lb_member_2_ipv6_subnet (optional)
        """

        # Create tenant VIP network
        network_kwargs = {
            'name': data_utils.rand_name("lb_member_vip_network")}
        if CONF.network_feature_enabled.port_security:
                # Note: Allowed Address Pairs requires port security
                network_kwargs['port_security_enabled'] = True
        result = cls.lb_mem_net_client.create_network(**network_kwargs)
        cls.lb_member_vip_net = result['network']
        LOG.info('lb_member_vip_net: {}'.format(cls.lb_member_vip_net))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_net_client.delete_network,
            cls.lb_mem_net_client.show_network,
            cls.lb_member_vip_net['id'])

        # Create tenant VIP subnet
        subnet_kwargs = {
            'name': data_utils.rand_name("lb_member_vip_subnet"),
            'network_id': cls.lb_member_vip_net['id'],
            'cidr': CONF.load_balancer.vip_subnet_cidr,
            'ip_version': 4}
        result = cls.lb_mem_subnet_client.create_subnet(**subnet_kwargs)
        cls.lb_member_vip_subnet = result['subnet']
        LOG.info('lb_member_vip_subnet: {}'.format(cls.lb_member_vip_subnet))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_subnet_client.delete_subnet,
            cls.lb_mem_subnet_client.show_subnet,
            cls.lb_member_vip_subnet['id'])

        # Create tenant VIP IPv6 subnet
        if CONF.load_balancer.test_with_ipv6:
            subnet_kwargs = {
                'name': data_utils.rand_name("lb_member_vip_ipv6_subnet"),
                'network_id': cls.lb_member_vip_net['id'],
                'cidr': CONF.load_balancer.vip_ipv6_subnet_cidr,
                'ip_version': 6}
            result = cls.lb_mem_subnet_client.create_subnet(**subnet_kwargs)
            cls.lb_member_vip_ipv6_subnet = result['subnet']
            LOG.info('lb_member_vip_ipv6_subnet: {}'.format(
                cls.lb_member_vip_ipv6_subnet))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_subnet_client.delete_subnet,
                cls.lb_mem_subnet_client.show_subnet,
                cls.lb_member_vip_ipv6_subnet['id'])

        # Create tenant member 1 network
        network_kwargs = {
            'name': data_utils.rand_name("lb_member_1_network")}
        if CONF.network_feature_enabled.port_security:
            if CONF.load_balancer.enable_security_groups:
                network_kwargs['port_security_enabled'] = True
            else:
                network_kwargs['port_security_enabled'] = False
        result = cls.lb_mem_net_client.create_network(**network_kwargs)
        cls.lb_member_1_net = result['network']
        LOG.info('lb_member_1_net: {}'.format(cls.lb_member_1_net))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_net_client.delete_network,
            cls.lb_mem_net_client.show_network,
            cls.lb_member_1_net['id'])

        # Create tenant member 1 subnet
        subnet_kwargs = {
            'name': data_utils.rand_name("lb_member_1_subnet"),
            'network_id': cls.lb_member_1_net['id'],
            'cidr': CONF.load_balancer.member_1_ipv4_subnet_cidr,
            'ip_version': 4}
        result = cls.lb_mem_subnet_client.create_subnet(**subnet_kwargs)
        cls.lb_member_1_subnet = result['subnet']
        LOG.info('lb_member_1_subnet: {}'.format(cls.lb_member_1_subnet))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_subnet_client.delete_subnet,
            cls.lb_mem_subnet_client.show_subnet,
            cls.lb_member_1_subnet['id'])

        # Create tenant member 1 ipv6 subnet
        if CONF.load_balancer.test_with_ipv6:
            subnet_kwargs = {
                'name': data_utils.rand_name("lb_member_1_ipv6_subnet"),
                'network_id': cls.lb_member_1_net['id'],
                'cidr': CONF.load_balancer.member_1_ipv6_subnet_cidr,
                'ip_version': 6}
            result = cls.lb_mem_subnet_client.create_subnet(**subnet_kwargs)
            cls.lb_member_1_ipv6_subnet = result['subnet']
            LOG.info('lb_member_1_ipv6_subnet: {}'.format(
                cls.lb_member_1_ipv6_subnet))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_subnet_client.delete_subnet,
                cls.lb_mem_subnet_client.show_subnet,
                cls.lb_member_1_ipv6_subnet['id'])

        # Create tenant member 2 network
        network_kwargs = {
            'name': data_utils.rand_name("lb_member_2_network")}
        if CONF.network_feature_enabled.port_security:
            if CONF.load_balancer.enable_security_groups:
                network_kwargs['port_security_enabled'] = True
            else:
                network_kwargs['port_security_enabled'] = False
        result = cls.lb_mem_net_client.create_network(**network_kwargs)
        cls.lb_member_2_net = result['network']
        LOG.info('lb_member_2_net: {}'.format(cls.lb_member_2_net))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_net_client.delete_network,
            cls.lb_mem_net_client.show_network,
            cls.lb_member_2_net['id'])

        # Create tenant member 2 subnet
        subnet_kwargs = {
            'name': data_utils.rand_name("lb_member_2_subnet"),
            'network_id': cls.lb_member_2_net['id'],
            'cidr': CONF.load_balancer.member_2_ipv4_subnet_cidr,
            'ip_version': 4}
        result = cls.lb_mem_subnet_client.create_subnet(**subnet_kwargs)
        cls.lb_member_2_subnet = result['subnet']
        LOG.info('lb_member_2_subnet: {}'.format(cls.lb_member_2_subnet))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_subnet_client.delete_subnet,
            cls.lb_mem_subnet_client.show_subnet,
            cls.lb_member_2_subnet['id'])

        # Create tenant member 2 ipv6 subnet
        if CONF.load_balancer.test_with_ipv6:
            subnet_kwargs = {
                'name': data_utils.rand_name("lb_member_2_ipv6_subnet"),
                'network_id': cls.lb_member_2_net['id'],
                'cidr': CONF.load_balancer.member_2_ipv6_subnet_cidr,
                'ip_version': 6}
            result = cls.lb_mem_subnet_client.create_subnet(**subnet_kwargs)
            cls.lb_member_2_ipv6_subnet = result['subnet']
            LOG.info('lb_member_2_ipv6_subnet: {}'.format(
                cls.lb_member_2_ipv6_subnet))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_subnet_client.delete_subnet,
                cls.lb_mem_subnet_client.show_subnet,
                cls.lb_member_2_ipv6_subnet['id'])

        # Create a router for the subnets (required for the floating IP)
        router_name = data_utils.rand_name("lb_member_router")
        result = cls.lb_mem_routers_client.create_router(
            name=router_name, admin_state_up=True,
            external_gateway_info=dict(
                network_id=CONF.network.public_network_id))
        cls.lb_member_router = result['router']
        LOG.info('lb_member_router: {}'.format(cls.lb_member_router))
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_routers_client.delete_router,
            cls.lb_mem_routers_client.show_router,
            cls.lb_member_router['id'])

        # Add VIP subnet to router
        cls.lb_mem_routers_client.add_router_interface(
            cls.lb_member_router['id'],
            subnet_id=cls.lb_member_vip_subnet['id'])
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_routers_client.remove_router_interface,
            cls.lb_mem_routers_client.remove_router_interface,
            cls.lb_member_router['id'],
            subnet_id=cls.lb_member_vip_subnet['id'])

        # Add member subnet 1 to router
        cls.lb_mem_routers_client.add_router_interface(
            cls.lb_member_router['id'],
            subnet_id=cls.lb_member_1_subnet['id'])
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_routers_client.remove_router_interface,
            cls.lb_mem_routers_client.remove_router_interface,
            cls.lb_member_router['id'], subnet_id=cls.lb_member_1_subnet['id'])

        # Add member subnet 2 to router
        cls.lb_mem_routers_client.add_router_interface(
            cls.lb_member_router['id'],
            subnet_id=cls.lb_member_2_subnet['id'])
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_routers_client.remove_router_interface,
            cls.lb_mem_routers_client.remove_router_interface,
            cls.lb_member_router['id'], subnet_id=cls.lb_member_2_subnet['id'])

    @classmethod
    def _create_webserver(cls, name, network):
        """Creates a webserver with two ports.

        webserver_details dictionary contains:
        server - The compute server object
        ipv4_address - The IPv4 address for the server (optional)
        ipv6_address - The IPv6 address for the server (optional)
        public_ipv4_address - The publicly accessible IPv4 address for the
                              server, this may be a floating IP (optional)

        :param name: The name of the server to create.
        :param network: The network to boot the server on.
        :returns: webserver_details dictionary.
        """
        server_kwargs = {
            'name': data_utils.rand_name(name),
            'flavorRef': CONF.compute.flavor_ref,
            'imageRef': CONF.compute.image_ref,
            'key_name': cls.lb_member_keypair['name']}
        if (CONF.load_balancer.enable_security_groups and
                CONF.network_feature_enabled.port_security):
            server_kwargs['security_groups'] = [
                {'name': cls.lb_member_sec_group['name']}]
        if not CONF.load_balancer.disable_boot_network:
            server_kwargs['networks'] = [{'uuid': network['id']}]

        # Replace the name for clouds that have limitations
        if CONF.load_balancer.random_server_name_length:
            r = random.SystemRandom()
            server_kwargs['name'] = "m{}".format("".join(
                [r.choice(string.ascii_uppercase + string.digits)
                 for _ in range(
                     CONF.load_balancer.random_server_name_length - 1)]
            ))
        if CONF.load_balancer.availability_zone:
            server_kwargs['availability_zone'] = (
                CONF.load_balancer.availability_zone)

        server = cls.lb_mem_servers_client.create_server(
            **server_kwargs)['server']
        cls.addClassResourceCleanup(
            waiters.wait_for_not_found,
            cls.lb_mem_servers_client.delete_server,
            cls.lb_mem_servers_client.show_server,
            server['id'])
        server = waiters.wait_for_status(
            cls.lb_mem_servers_client.show_server,
            server['id'], 'status', 'ACTIVE',
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            root_tag='server')
        webserver_details = {'server': server}
        LOG.info('Created server: {}'.format(server))

        addresses = server['addresses']
        if CONF.load_balancer.disable_boot_network:
            instance_network = addresses.values()[0]
        else:
            instance_network = addresses[network['name']]
        for addr in instance_network:
            if addr['version'] == 4:
                webserver_details['ipv4_address'] = addr['addr']
            if addr['version'] == 6:
                webserver_details['ipv6_address'] = addr['addr']

        if CONF.validation.connect_method == 'floating':
            result = cls.lb_mem_ports_client.list_ports(
                network_id=network['id'],
                mac_address=instance_network[0]['OS-EXT-IPS-MAC:mac_addr'])
            port_id = result['ports'][0]['id']
            result = cls.lb_mem_float_ip_client.create_floatingip(
                floating_network_id=CONF.network.public_network_id,
                port_id=port_id)
            floating_ip = result['floatingip']
            LOG.info('webserver1_floating_ip: {}'.format(floating_ip))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_float_ip_client.delete_floatingip,
                cls.lb_mem_float_ip_client.show_floatingip,
                floatingip_id=floating_ip['id'])
            webserver_details['public_ipv4_address'] = (
                floating_ip['floating_ip_address'])
        else:
            webserver_details['public_ipv4_address'] = (
                instance_network[0]['addr'])

        return webserver_details

    @classmethod
    def _validate_webserver(cls, ip_address, start_id):
        URL = 'http://{0}'.format(ip_address)
        validators.validate_URL_response(URL, expected_body=str(start_id))
        URL = 'http://{0}:81'.format(ip_address)
        validators.validate_URL_response(URL, expected_body=str(start_id + 1))

    @classmethod
    def _setup_lb_network_kwargs(cls, lb_kwargs, ip_version):
        if cls.lb_member_vip_subnet:
            ip_index = data_utils.rand_int_id(start=10, end=100)
            if ip_version == 4:
                network = ipaddress.IPv4Network(
                    six.u(CONF.load_balancer.vip_subnet_cidr))
                lb_vip_address = str(network[ip_index])
                subnet_id = cls.lb_member_vip_subnet[const.ID]
            else:
                network = ipaddress.IPv6Network(
                    six.u(CONF.load_balancer.vip_ipv6_subnet_cidr))
                lb_vip_address = str(network[ip_index])
                subnet_id = cls.lb_member_vip_ipv6_subnet[const.ID]
            lb_kwargs[const.VIP_SUBNET_ID] = subnet_id
            lb_kwargs[const.VIP_ADDRESS] = lb_vip_address
            if CONF.load_balancer.test_with_noop:
                lb_kwargs[const.VIP_NETWORK_ID] = (
                    cls.lb_member_vip_net[const.ID])
        else:
            lb_kwargs[const.VIP_NETWORK_ID] = cls.lb_member_vip_net[const.ID]
            lb_kwargs[const.VIP_SUBNET_ID] = None
