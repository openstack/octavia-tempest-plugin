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
import requests
import shlex
import six
import string
import subprocess
import tempfile
import time

from oslo_log import log as logging
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.linux import remote_client
from tempest.lib import exceptions
from tempest import test
import tenacity

from octavia_tempest_plugin import clients
from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import validators
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


class LoadBalancerBaseTest(test.BaseTestCase):
    """Base class for load balancer tests."""

    # Setup cls.os_roles_lb_member. cls.os_primary, cls.os_roles_lb_member,
    # and cls.os_roles_lb_admin credentials.
    credentials = ['admin', 'primary',
                   ['lb_member', CONF.load_balancer.member_role],
                   ['lb_member2', CONF.load_balancer.member_role],
                   ['lb_admin', CONF.load_balancer.admin_role]]

    client_manager = clients.ManagerV2
    webserver1_response = 1
    webserver2_response = 5
    used_ips = []

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
                skip_msg = ("{0} skipped as {1} service is not "
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
        cls.mem_member_client = cls.os_roles_lb_member.member_client
        cls.mem_healthmonitor_client = (
            cls.os_roles_lb_member.healthmonitor_client)
        cls.mem_l7policy_client = cls.os_roles_lb_member.l7policy_client
        cls.mem_l7rule_client = cls.os_roles_lb_member.l7rule_client
        cls.mem_amphora_client = cls.os_roles_lb_member.amphora_client
        cls.lb_admin_flavor_profile_client = (
            cls.os_roles_lb_admin.flavor_profile_client)
        cls.lb_admin_flavor_client = cls.os_roles_lb_admin.flavor_client
        cls.mem_flavor_client = cls.os_roles_lb_member.flavor_client
        cls.mem_provider_client = cls.os_roles_lb_member.provider_client

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(LoadBalancerBaseTest, cls).resource_setup()

        conf_lb = CONF.load_balancer

        cls.api_version = cls.mem_lb_client.get_max_api_version()

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
                cls.lb_member_vip_ipv6_net = {'id': uuidutils.generate_uuid()}
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
        if CONF.load_balancer.test_with_ipv6:
            if cls.lb_member_vip_ipv6_subnet:
                LOG.debug('Octavia Setup: lb_member_vip_ipv6_subnet = '
                          '{}'.format(cls.lb_member_vip_ipv6_subnet[const.ID]))
            if cls.lb_member_1_ipv6_subnet:
                LOG.debug('Octavia Setup: lb_member_1_ipv6_subnet = {}'.format(
                    cls.lb_member_1_ipv6_subnet[const.ID]))
            if cls.lb_member_2_ipv6_subnet:
                LOG.debug('Octavia Setup: lb_member_2_ipv6_subnet = {}'.format(
                    cls.lb_member_2_ipv6_subnet[const.ID]))

    @classmethod
    # Neutron can be slow to clean up ports from the subnets/networks.
    # Retry this delete a few times if we get a "Conflict" error to give
    # neutron time to fully cleanup the ports.
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(exceptions.Conflict),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _logging_delete_network(cls, net_id):
        try:
            cls.lb_mem_net_client.delete_network(net_id)
        except Exception:
            LOG.error('Unable to delete network {}. Active ports:'.format(
                net_id))
            LOG.error(cls.lb_mem_ports_client.list_ports())
            raise

    @classmethod
    # Neutron can be slow to clean up ports from the subnets/networks.
    # Retry this delete a few times if we get a "Conflict" error to give
    # neutron time to fully cleanup the ports.
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(exceptions.Conflict),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _logging_delete_subnet(cls, subnet_id):
        try:
            cls.lb_mem_subnet_client.delete_subnet(subnet_id)
        except Exception:
            LOG.error('Unable to delete subnet {}. Active ports:'.format(
                subnet_id))
            LOG.error(cls.lb_mem_ports_client.list_ports())
            raise

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
            cls._logging_delete_network,
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
            cls._logging_delete_subnet,
            cls.lb_mem_subnet_client.show_subnet,
            cls.lb_member_vip_subnet['id'])

        # Create tenant VIP IPv6 subnet
        if CONF.load_balancer.test_with_ipv6:
            # See if ipv6-public-subnet exists and use it if so.
            pub_ipv6_subnet = cls.os_admin.subnets_client.list_subnets(
                name='ipv6-public-subnet')['subnets']

            if len(pub_ipv6_subnet) == 1:
                cls.lb_member_vip_ipv6_subnet = pub_ipv6_subnet[0]
                cls.lb_member_vip_ipv6_net = {
                    'id': pub_ipv6_subnet[0]['network_id']}
            else:
                subnet_kwargs = {
                    'name': data_utils.rand_name("lb_member_vip_ipv6_subnet"),
                    'network_id': cls.lb_member_vip_net['id'],
                    'cidr': CONF.load_balancer.vip_ipv6_subnet_cidr,
                    'ip_version': 6}
                result = cls.lb_mem_subnet_client.create_subnet(
                    **subnet_kwargs)
                cls.lb_member_vip_ipv6_subnet = result['subnet']
                cls.addClassResourceCleanup(
                    waiters.wait_for_not_found,
                    cls._logging_delete_subnet,
                    cls.lb_mem_subnet_client.show_subnet,
                    cls.lb_member_vip_ipv6_subnet['id'])
            LOG.info('lb_member_vip_ipv6_subnet: {}'.format(
                cls.lb_member_vip_ipv6_subnet))

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
            cls._logging_delete_network,
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
            cls._logging_delete_subnet,
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
            cls.lb_member_1_subnet_prefix = (
                CONF.load_balancer.member_1_ipv6_subnet_cidr.rpartition('/')[2]
                )
            assert(cls.lb_member_1_subnet_prefix.isdigit())
            cls.lb_member_1_ipv6_subnet = result['subnet']
            LOG.info('lb_member_1_ipv6_subnet: {}'.format(
                cls.lb_member_1_ipv6_subnet))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls._logging_delete_subnet,
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
            cls._logging_delete_network,
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
            cls._logging_delete_subnet,
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
            cls.lb_member_2_subnet_prefix = (
                CONF.load_balancer.member_2_ipv6_subnet_cidr.rpartition('/')[2]
                )
            assert(cls.lb_member_2_subnet_prefix.isdigit())
            cls.lb_member_2_ipv6_subnet = result['subnet']
            LOG.info('lb_member_2_ipv6_subnet: {}'.format(
                cls.lb_member_2_ipv6_subnet))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls._logging_delete_subnet,
                cls.lb_mem_subnet_client.show_subnet,
                cls.lb_member_2_ipv6_subnet['id'])

    @classmethod
    def _setup_lb_network_kwargs(cls, lb_kwargs, ip_version=None,
                                 use_fixed_ip=False):
        if not ip_version:
            ip_version = 6 if CONF.load_balancer.test_with_ipv6 else 4
        if cls.lb_member_vip_subnet or cls.lb_member_vip_ipv6_subnet:
            ip_index = data_utils.rand_int_id(start=10, end=100)
            while ip_index in cls.used_ips:
                ip_index = data_utils.rand_int_id(start=10, end=100)
            cls.used_ips.append(ip_index)
            if ip_version == 4:
                subnet_id = cls.lb_member_vip_subnet[const.ID]
                if CONF.load_balancer.test_with_noop:
                    lb_vip_address = '198.18.33.33'
                else:
                    subnet = cls.os_admin.subnets_client.show_subnet(subnet_id)
                    network = ipaddress.IPv4Network(subnet['subnet']['cidr'])
                    lb_vip_address = str(network[ip_index])
            else:
                subnet_id = cls.lb_member_vip_ipv6_subnet[const.ID]
                if CONF.load_balancer.test_with_noop:
                    lb_vip_address = '2001:db8:33:33:33:33:33:33'
                else:
                    subnet = cls.os_admin.subnets_client.show_subnet(subnet_id)
                    network = ipaddress.IPv6Network(subnet['subnet']['cidr'])
                    lb_vip_address = str(network[ip_index])
            lb_kwargs[const.VIP_SUBNET_ID] = subnet_id
            if use_fixed_ip:
                lb_kwargs[const.VIP_ADDRESS] = lb_vip_address
            if CONF.load_balancer.test_with_noop:
                lb_kwargs[const.VIP_NETWORK_ID] = (
                    cls.lb_member_vip_net[const.ID])
        else:
            lb_kwargs[const.VIP_NETWORK_ID] = cls.lb_member_vip_net[const.ID]
            lb_kwargs[const.VIP_SUBNET_ID] = None


class LoadBalancerBaseTestWithCompute(LoadBalancerBaseTest):
    @classmethod
    def resource_setup(cls):
        super(LoadBalancerBaseTestWithCompute, cls).resource_setup()
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

        if CONF.load_balancer.test_with_ipv6:
            # Enable the IPv6 nic in webserver 1
            cls._enable_ipv6_nic_webserver(
                cls.webserver1_public_ip, cls.lb_member_keypair['private_key'],
                cls.webserver1_ipv6, cls.lb_member_1_subnet_prefix)

            # Enable the IPv6 nic in webserver 2
            cls._enable_ipv6_nic_webserver(
                cls.webserver2_public_ip, cls.lb_member_keypair['private_key'],
                cls.webserver2_ipv6, cls.lb_member_2_subnet_prefix)

        # Set up serving on webserver 1
        cls._install_start_webserver(cls.webserver1_public_ip,
                                     cls.lb_member_keypair['private_key'],
                                     cls.webserver1_response)

        # Validate webserver 1
        cls._validate_webserver(cls.webserver1_public_ip,
                                cls.webserver1_response)

        # Set up serving on webserver 2
        cls._install_start_webserver(cls.webserver2_public_ip,
                                     cls.lb_member_keypair['private_key'],
                                     cls.webserver2_response)

        # Validate webserver 2
        cls._validate_webserver(cls.webserver2_public_ip,
                                cls.webserver2_response)

    @classmethod
    def _create_networks(cls):
        super(LoadBalancerBaseTestWithCompute, cls)._create_networks()
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

    # Cirros does not configure the assigned IPv6 address by default
    # so enable it manually like tempest does here:
    # tempest/scenario/test_netowrk_v6.py turn_nic6_on()
    @classmethod
    def _enable_ipv6_nic_webserver(cls, ip_address, ssh_key,
                                   ipv6_address, ipv6_prefix):
        linux_client = remote_client.RemoteClient(
            ip_address, CONF.validation.image_ssh_user, pkey=ssh_key)
        linux_client.validate_authentication()

        linux_client.exec_command('sudo ip address add {0}/{1} dev '
                                  'eth0'.format(ipv6_address, ipv6_prefix))

    @classmethod
    def _validate_webserver(cls, ip_address, start_id):
        URL = 'http://{0}'.format(ip_address)
        validators.validate_URL_response(URL, expected_body=str(start_id))
        URL = 'http://{0}:81'.format(ip_address)
        validators.validate_URL_response(URL, expected_body=str(start_id + 1))

    def _wait_for_lb_functional(self, vip_address,
                                protocol='http', verify=True):
        session = requests.Session()
        start = time.time()

        while time.time() - start < CONF.load_balancer.build_timeout:
            try:
                session.get("{0}://{1}".format(protocol, vip_address),
                            timeout=2, verify=verify)
                time.sleep(1)
                return
            except Exception:
                LOG.warning('Server is not passing initial traffic. Waiting.')
                time.sleep(1)
        LOG.error('Server did not begin passing traffic within the timeout '
                  'period. Failing test.')
        raise Exception()

    def check_members_balanced(self, vip_address, traffic_member_count=2,
                               protocol='http', verify=True):
        session = requests.Session()
        response_counts = {}

        if ipaddress.ip_address(vip_address).version == 6:
            vip_address = '[{}]'.format(vip_address)

        self._wait_for_lb_functional(vip_address, protocol, verify)

        # Send a number requests to lb vip
        for i in range(20):
            try:
                r = session.get('{0}://{1}'.format(protocol, vip_address),
                                timeout=2, verify=verify)

                if r.content in response_counts:
                    response_counts[r.content] += 1
                else:
                    response_counts[r.content] = 1

            except Exception:
                LOG.exception('Failed to send request to loadbalancer vip')
                raise Exception('Failed to connect to lb')

        LOG.debug('Loadbalancer response totals: %s', response_counts)
        # Ensure the correct number of members
        self.assertEqual(traffic_member_count, len(response_counts))

        # Ensure both members got the same number of responses
        self.assertEqual(1, len(set(response_counts.values())))

    def assertConsistentResponse(self, response, url, method='GET', repeat=10,
                                 redirect=False, timeout=2, **kwargs):
        """Assert that a request to URL gets the expected response.

        :param response: Expected response in format (status_code, content).
        :param url: The URL to request.
        :param method: The HTTP method to use (GET, POST, PUT, etc)
        :param repeat: How many times to test the response.
        :param data: Optional data to send in the request.
        :param headers: Optional headers to send in the request.
        :param cookies: Optional cookies to send in the request.
        :param redirect: Is the request a redirect? If true, assume the passed
                         content should be the next URL in the chain.
        :param timeout: Optional seconds to wait for the server to send data.

        :return: boolean success status

        :raises: testtools.matchers.MismatchError
        """
        session = requests.Session()
        response_code, response_content = response

        for i in range(0, repeat):
            req = session.request(method, url, allow_redirects=not redirect,
                                  timeout=timeout, **kwargs)
            if response_code:
                self.assertEqual(response_code, req.status_code)
            if redirect:
                self.assertTrue(req.is_redirect)
                self.assertEqual(response_content,
                                 session.get_redirect_target(req))
            elif response_content:
                self.assertEqual(six.text_type(response_content), req.text)
