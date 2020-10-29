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
import os
import random
import re
import shlex
import string
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.linux import remote_client
from tempest.lib import exceptions
from tempest import test
import tenacity

from octavia_tempest_plugin.common import cert_utils
from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import RBAC_tests
from octavia_tempest_plugin.tests import validators
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


class LoadBalancerBaseTest(validators.ValidatorsMixin,
                           RBAC_tests.RBACTestsMixin, test.BaseTestCase):
    """Base class for load balancer tests."""

    if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
        credentials = [
            'admin', 'primary', ['lb_admin', CONF.load_balancer.admin_role],
            ['lb_member', CONF.load_balancer.member_role],
            ['lb_member2', CONF.load_balancer.member_role]]
    elif CONF.load_balancer.enforce_new_defaults:
        credentials = [
            'admin', 'primary', ['lb_admin', CONF.load_balancer.admin_role],
            ['lb_observer', CONF.load_balancer.observer_role, 'reader'],
            ['lb_global_observer', CONF.load_balancer.global_observer_role,
             'reader'],
            ['lb_member', CONF.load_balancer.member_role, 'member'],
            ['lb_member2', CONF.load_balancer.member_role, 'member'],
            ['lb_member_not_default_member', CONF.load_balancer.member_role]]
    else:
        credentials = [
            'admin', 'primary', ['lb_admin', CONF.load_balancer.admin_role],
            ['lb_observer', CONF.load_balancer.observer_role, 'reader'],
            ['lb_global_observer', CONF.load_balancer.global_observer_role,
             'reader'],
            ['lb_member', CONF.load_balancer.member_role],
            ['lb_member2', CONF.load_balancer.member_role]]

    # If scope enforcement is enabled, add in the system scope credentials.
    # The project scope is already handled by the above credentials.
    if CONF.enforce_scope.octavia:
        credentials.extend(['system_admin', 'system_reader'])

    # A tuple of credentials that will be allocated by tempest using the
    # 'credentials' list above. These are used to build RBAC test lists.
    allocated_creds = []
    for cred in credentials:
        if isinstance(cred, list):
            allocated_creds.append('os_roles_' + cred[0])
        else:
            allocated_creds.append('os_' + cred)
    # Tests shall not mess with the list of allocated credentials
    allocated_credentials = tuple(allocated_creds)

    webserver1_response = 1
    webserver2_response = 5
    used_ips = []

    SRC_PORT_NUMBER_MIN = 32768
    SRC_PORT_NUMBER_MAX = 61000
    src_port_number = SRC_PORT_NUMBER_MIN

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

        # Log the user roles for this test run
        role_name_cache = {}
        for cred in cls.credentials:
            user_roles = []
            if isinstance(cred, list):
                user_name = cred[0]
                cred_obj = getattr(cls, 'os_roles_' + cred[0])
            else:
                user_name = cred
                cred_obj = getattr(cls, 'os_' + cred)
            params = {'user.id': cred_obj.credentials.user_id,
                      'project.id': cred_obj.credentials.project_id}
            roles = cls.os_admin.role_assignments_client.list_role_assignments(
                **params)['role_assignments']
            for role in roles:
                role_id = role['role']['id']
                try:
                    role_name = role_name_cache[role_id]
                except KeyError:
                    role_name = cls.os_admin.roles_v3_client.show_role(
                        role_id)['role']['name']
                    role_name_cache[role_id] = role_name
                user_roles.append([role_name, role['scope']])
            LOG.info("User %s has roles: %s", user_name, user_roles)

    @classmethod
    def setup_clients(cls):
        """Setup client aliases."""
        super(LoadBalancerBaseTest, cls).setup_clients()
        lb_admin_prefix = cls.os_roles_lb_admin.load_balancer_v2
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
        cls.mem_lb_client = (
            cls.os_roles_lb_member.load_balancer_v2.LoadbalancerClient())
        cls.mem_listener_client = (
            cls.os_roles_lb_member.load_balancer_v2.ListenerClient())
        cls.mem_pool_client = (
            cls.os_roles_lb_member.load_balancer_v2.PoolClient())
        cls.mem_member_client = (
            cls.os_roles_lb_member.load_balancer_v2.MemberClient())
        cls.mem_healthmonitor_client = (
            cls.os_roles_lb_member.load_balancer_v2.HealthMonitorClient())
        cls.mem_l7policy_client = (
            cls.os_roles_lb_member.load_balancer_v2.L7PolicyClient())
        cls.mem_l7rule_client = (
            cls.os_roles_lb_member.load_balancer_v2.L7RuleClient())
        cls.lb_admin_amphora_client = lb_admin_prefix.AmphoraClient()
        cls.lb_admin_flavor_profile_client = (
            lb_admin_prefix.FlavorProfileClient())
        cls.lb_admin_flavor_client = lb_admin_prefix.FlavorClient()
        cls.mem_flavor_client = (
            cls.os_roles_lb_member.load_balancer_v2.FlavorClient())
        cls.mem_provider_client = (
            cls.os_roles_lb_member.load_balancer_v2.ProviderClient())
        cls.os_admin_servers_client = cls.os_admin.servers_client
        cls.os_admin_routers_client = cls.os_admin.routers_client
        cls.os_admin_subnetpools_client = cls.os_admin.subnetpools_client
        cls.lb_admin_flavor_capabilities_client = (
            lb_admin_prefix.FlavorCapabilitiesClient())
        cls.lb_admin_availability_zone_capabilities_client = (
            lb_admin_prefix.AvailabilityZoneCapabilitiesClient())
        cls.lb_admin_availability_zone_profile_client = (
            lb_admin_prefix.AvailabilityZoneProfileClient())
        cls.lb_admin_availability_zone_client = (
            lb_admin_prefix.AvailabilityZoneClient())
        cls.mem_availability_zone_client = (
            cls.os_roles_lb_member.load_balancer_v2.AvailabilityZoneClient())

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

        # TODO(johnsom) Remove this
        # Get loadbalancing algorithms supported by provider driver.
        try:
            algorithms = const.SUPPORTED_LB_ALGORITHMS[
                CONF.load_balancer.provider]
        except KeyError:
            algorithms = const.SUPPORTED_LB_ALGORITHMS['default']
        # Set default algorithm as first from the list.
        cls.lb_algorithm = algorithms[0]

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
                cls.lb_member_vip_ipv6_subnet_stateful = True
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
                cls.lb_member_vip_ipv6_subnet_stateful = False
                if (override_ipv6_subnet[0]['ipv6_address_mode'] ==
                        'dhcpv6-stateful'):
                    cls.lb_member_vip_ipv6_subnet_stateful = True
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
            cls.lb_member_vip_ipv6_subnet_stateful = False
            cls.lb_member_vip_ipv6_subnet_use_subnetpool = False
            subnet_kwargs = {
                'name': data_utils.rand_name("lb_member_vip_ipv6_subnet"),
                'network_id': cls.lb_member_vip_net['id'],
                'ip_version': 6}

            # Use a CIDR from devstack's default IPv6 subnetpool if it exists,
            # the subnetpool's cidr is routable from the devstack node
            # through the default router
            subnetpool_name = CONF.load_balancer.default_ipv6_subnetpool
            if subnetpool_name:
                subnetpool = cls.os_admin_subnetpools_client.list_subnetpools(
                    name=subnetpool_name)['subnetpools']
                if len(subnetpool) == 1:
                    subnetpool = subnetpool[0]
                    subnet_kwargs['subnetpool_id'] = subnetpool['id']
                    cls.lb_member_vip_ipv6_subnet_use_subnetpool = True

            if 'subnetpool_id' not in subnet_kwargs:
                subnet_kwargs['cidr'] = (
                    CONF.load_balancer.vip_ipv6_subnet_cidr)

            result = cls.lb_mem_subnet_client.create_subnet(
                **subnet_kwargs)
            cls.lb_member_vip_ipv6_net = cls.lb_member_vip_net
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
                    # If the subnet is IPv6 slaac or dhcpv6-stateless
                    # neutron does not allow a fixed IP
                    if not cls.lb_member_vip_ipv6_subnet_stateful:
                        use_fixed_ip = False
            lb_kwargs[const.VIP_SUBNET_ID] = subnet_id
            if use_fixed_ip:
                lb_kwargs[const.VIP_ADDRESS] = lb_vip_address
            if CONF.load_balancer.test_with_noop:
                lb_kwargs[const.VIP_NETWORK_ID] = (
                    cls.lb_member_vip_net[const.ID])
                if ip_version == 6:
                    lb_kwargs[const.VIP_ADDRESS] = lb_vip_address
        else:
            lb_kwargs[const.VIP_NETWORK_ID] = cls.lb_member_vip_net[const.ID]
            lb_kwargs[const.VIP_SUBNET_ID] = None


class LoadBalancerBaseTestWithCompute(LoadBalancerBaseTest):
    @classmethod
    def remote_client_args(cls):
        # In case we're using octavia-tempest-plugin with old tempest releases
        # (for instance on stable/train) that don't support ssh_key_type, catch
        # the exception and don't pass any argument
        args = {}
        try:
            args['ssh_key_type'] = CONF.validation.ssh_key_type
        except cfg.NoSuchOptError:
            pass
        return args

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
            # Create a security group rule to allow UDP 80-81 (test webservers)
            SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                direction='ingress',
                security_group_id=cls.lb_member_sec_group['id'],
                protocol='udp',
                ethertype='IPv4',
                port_range_min=80,
                port_range_max=81)['security_group_rule']
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_SGr_client.delete_security_group_rule,
                cls.lb_mem_SGr_client.show_security_group_rule,
                SGr['id'])
            # Create a security group rule to allow 443 (test webservers)
            SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                direction='ingress',
                security_group_id=cls.lb_member_sec_group['id'],
                protocol='tcp',
                ethertype='IPv4',
                port_range_min=443,
                port_range_max=443)['security_group_rule']
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_SGr_client.delete_security_group_rule,
                cls.lb_mem_SGr_client.show_security_group_rule,
                SGr['id'])
            # Create a security group rule to allow 9443 (test webservers)
            # Used in the pool backend encryption client authentication tests
            SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                direction='ingress',
                security_group_id=cls.lb_member_sec_group['id'],
                protocol='tcp',
                ethertype='IPv4',
                port_range_min=9443,
                port_range_max=9443)['security_group_rule']
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_SGr_client.delete_security_group_rule,
                cls.lb_mem_SGr_client.show_security_group_rule,
                SGr['id'])
            # Create a security group rule to allow UDP 9999 (test webservers)
            # Port 9999 is used to illustrate health monitor ERRORs on closed
            # ports.
            SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                direction='ingress',
                security_group_id=cls.lb_member_sec_group['id'],
                protocol='udp',
                ethertype='IPv4',
                port_range_min=9999,
                port_range_max=9999)['security_group_rule']
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
                # Create a security group rule to allow UDP 80-81 (test
                # webservers)
                SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                    direction='ingress',
                    security_group_id=cls.lb_member_sec_group['id'],
                    protocol='udp',
                    ethertype='IPv6',
                    port_range_min=80,
                    port_range_max=81)['security_group_rule']
                cls.addClassResourceCleanup(
                    waiters.wait_for_not_found,
                    cls.lb_mem_SGr_client.delete_security_group_rule,
                    cls.lb_mem_SGr_client.show_security_group_rule,
                    SGr['id'])
                # Create a security group rule to allow 443 (test webservers)
                SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                    direction='ingress',
                    security_group_id=cls.lb_member_sec_group['id'],
                    protocol='tcp',
                    ethertype='IPv6',
                    port_range_min=443,
                    port_range_max=443)['security_group_rule']
                cls.addClassResourceCleanup(
                    waiters.wait_for_not_found,
                    cls.lb_mem_SGr_client.delete_security_group_rule,
                    cls.lb_mem_SGr_client.show_security_group_rule,
                    SGr['id'])
                # Create a security group rule to allow 9443 (test webservers)
                # Used in the pool encryption client authentication tests
                SGr = cls.lb_mem_SGr_client.create_security_group_rule(
                    direction='ingress',
                    security_group_id=cls.lb_member_sec_group['id'],
                    protocol='tcp',
                    ethertype='IPv6',
                    port_range_min=9443,
                    port_range_max=9443)['security_group_rule']
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

        # Setup backend member reencryption PKI
        cls._create_backend_reencryption_pki()

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

        # Validate udp server 1
        cls._validate_udp_server(cls.webserver1_public_ip,
                                 cls.webserver1_response)

        # Set up serving on webserver 2
        cls._install_start_webserver(cls.webserver2_public_ip,
                                     cls.lb_member_keypair['private_key'],
                                     cls.webserver2_response, revoke_cert=True)

        # Validate webserver 2
        cls._validate_webserver(cls.webserver2_public_ip,
                                cls.webserver2_response)

        # Validate udp server 2
        cls._validate_udp_server(cls.webserver2_public_ip,
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

        if (CONF.load_balancer.test_with_ipv6 and
                CONF.load_balancer.default_router and
                cls.lb_member_vip_ipv6_subnet_use_subnetpool):

            router_name = CONF.load_balancer.default_router
            # if lb_member_vip_ipv6_subnet uses devstack's subnetpool,
            # plug the subnet into the default router
            router = cls.os_admin.routers_client.list_routers(
                name=router_name)['routers']

            if len(router) == 1:
                router = router[0]

                # Add IPv6 VIP subnet to router1
                cls.os_admin_routers_client.add_router_interface(
                    router['id'],
                    subnet_id=cls.lb_member_vip_ipv6_subnet['id'])
                cls.addClassResourceCleanup(
                    waiters.wait_for_not_found,
                    cls.os_admin_routers_client.remove_router_interface,
                    cls.os_admin_routers_client.remove_router_interface,
                    router['id'],
                    subnet_id=cls.lb_member_vip_ipv6_subnet['id'])

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
    def _get_openssh_version(cls):
        p = subprocess.Popen(["ssh", "-V"],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output = p.communicate()[1]

        try:
            m = re.match(r"OpenSSH_(\d+)\.(\d+)", output.decode('utf-8'))
            version_maj = int(m.group(1))
            version_min = int(m.group(2))
            return version_maj, version_min
        except Exception:
            return None, None

    @classmethod
    def _need_scp_protocol(cls):
        # When using scp >= 8.7, force the use of the SCP protocol,
        # the new default (SFTP protocol) doesn't work with
        # cirros VMs.
        ssh_version = cls._get_openssh_version()
        LOG.debug("ssh_version = {}".format(ssh_version))
        return (ssh_version[0] > 8 or
                (ssh_version[0] == 8 and ssh_version[1] >= 7))

    @classmethod
    def _install_start_webserver(cls, ip_address, ssh_key, start_id,
                                 revoke_cert=False):
        local_file = CONF.load_balancer.test_server_path

        linux_client = remote_client.RemoteClient(
            ip_address, CONF.validation.image_ssh_user, pkey=ssh_key,
            **cls.remote_client_args())
        linux_client.validate_authentication()

        with tempfile.NamedTemporaryFile() as key:
            key.write(ssh_key.encode('utf-8'))
            key.flush()
            ssh_extra_args = (
                "-o PubkeyAcceptedKeyTypes=+ssh-rsa")
            if cls._need_scp_protocol():
                ssh_extra_args += " -O"
            cmd = ("scp -v -o UserKnownHostsFile=/dev/null "
                   "{7} "
                   "-o StrictHostKeyChecking=no "
                   "-o ConnectTimeout={0} -o ConnectionAttempts={1} "
                   "-i {2} {3} {4}@{5}:{6}").format(
                CONF.load_balancer.scp_connection_timeout,
                CONF.load_balancer.scp_connection_attempts,
                key.name, local_file, CONF.validation.image_ssh_user,
                ip_address, const.TEST_SERVER_BINARY,
                ssh_extra_args)
            args = shlex.split(cmd)
            subprocess_args = {'stdout': subprocess.PIPE,
                               'stderr': subprocess.STDOUT,
                               'cwd': None}
            proc = subprocess.Popen(args, **subprocess_args)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                raise exceptions.CommandFailed(proc.returncode, cmd,
                                               stdout, stderr)

            cls._load_member_pki_content(ip_address, key,
                                         revoke_cert=revoke_cert)

        # Enabling memory overcommit allows to run golang static binaries
        # compiled with a recent golang toolchain (>=1.11). Those binaries
        # allocate a large amount of virtual memory at init time, and this
        # allocation fails in tempest's nano flavor (64MB of RAM)
        # (golang issue reported in https://github.com/golang/go/issues/28114,
        # follow-up: https://github.com/golang/go/issues/28081)
        # TODO(gthiemonge): Remove this call when golang issue is resolved.
        linux_client.exec_command('sudo sh -c "echo 1 > '
                                  '/proc/sys/vm/overcommit_memory"')

        # The initial process also supports HTTPS and HTTPS with client auth
        linux_client.exec_command(
            'sudo screen -d -m {0} -port 80 -id {1} -https_port 443 -cert {2} '
            '-key {3} -https_client_auth_port 9443 -client_ca {4}'.format(
                const.TEST_SERVER_BINARY, start_id, const.TEST_SERVER_CERT,
                const.TEST_SERVER_KEY, const.TEST_SERVER_CLIENT_CA))

        linux_client.exec_command('sudo screen -d -m {0} -port 81 '
                                  '-id {1}'.format(const.TEST_SERVER_BINARY,
                                                   start_id + 1))

    # Cirros does not configure the assigned IPv6 address by default
    # so enable it manually like tempest does here:
    # tempest/scenario/test_netowrk_v6.py turn_nic6_on()
    @classmethod
    def _enable_ipv6_nic_webserver(cls, ip_address, ssh_key,
                                   ipv6_address, ipv6_prefix):
        linux_client = remote_client.RemoteClient(
            ip_address, CONF.validation.image_ssh_user, pkey=ssh_key,
            **cls.remote_client_args())
        linux_client.validate_authentication()

        linux_client.exec_command('sudo ip address add {0}/{1} dev '
                                  'eth0'.format(ipv6_address, ipv6_prefix))

    @classmethod
    def _validate_webserver(cls, ip_address, start_id):
        URL = 'http://{0}'.format(ip_address)
        cls.validate_URL_response(URL, expected_body=str(start_id))
        URL = 'http://{0}:81'.format(ip_address)
        cls.validate_URL_response(URL, expected_body=str(start_id + 1))

    @classmethod
    def _validate_udp_server(cls, ip_address, start_id):
        res = cls.make_udp_request(ip_address, 80)
        if res != str(start_id):
            raise Exception("Response from test server doesn't match the "
                            "expected value ({0} != {1}).".format(
                                res, str(start_id)))

        res = cls.make_udp_request(ip_address, 81)
        if res != str(start_id + 1):
            raise Exception("Response from test server doesn't match the "
                            "expected value ({0} != {1}).".format(
                                res, str(start_id + 1)))

    @classmethod
    def _create_backend_reencryption_pki(cls):
        # Create a CA self-signed cert and key for the member test servers
        cls.member_ca_cert, cls.member_ca_key = (
            cert_utils.generate_ca_cert_and_key())

        LOG.debug('Member CA Cert: %s', cls.member_ca_cert.public_bytes(
            serialization.Encoding.PEM))
        LOG.debug('Member CA private Key: %s', cls.member_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        LOG.debug('Member CA public Key: %s',
                  cls.member_ca_key.public_key().public_bytes(
                      encoding=serialization.Encoding.PEM,
                      format=serialization.PublicFormat.SubjectPublicKeyInfo))

        # Create the member client authentication CA
        cls.member_client_ca_cert, member_client_ca_key = (
            cert_utils.generate_ca_cert_and_key())

        # Create client cert and key
        cls.member_client_cn = uuidutils.generate_uuid()
        cls.member_client_cert, cls.member_client_key = (
            cert_utils.generate_client_cert_and_key(
                cls.member_client_ca_cert, member_client_ca_key,
                cls.member_client_cn))
        # Note: We are not revoking a client cert here as we don't need to
        #       test the backend web server CRL checking.

    @classmethod
    def _load_member_pki_content(cls, ip_address, ssh_key, revoke_cert=False):
        # Create webserver certificate and key
        cert, key = cert_utils.generate_server_cert_and_key(
            cls.member_ca_cert, cls.member_ca_key, ip_address)

        LOG.debug('%s Cert: %s', ip_address, cert.public_bytes(
            serialization.Encoding.PEM))
        LOG.debug('%s private Key: %s', ip_address, key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        public_key = key.public_key()
        LOG.debug('%s public Key: %s', ip_address, public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

        # Create a CRL with a revoked certificate
        if revoke_cert:
            # Create a CRL with webserver 2 revoked
            cls.member_crl = cert_utils.generate_certificate_revocation_list(
                cls.member_ca_cert, cls.member_ca_key, cert)

        # Load the certificate, key, and client CA certificate into the
        # test server.
        with tempfile.TemporaryDirectory() as tmpdir:
            os.umask(0)
            files_to_send = []
            cert_filename = os.path.join(tmpdir, const.CERT_PEM)
            files_to_send.append(cert_filename)
            with open(os.open(cert_filename, os.O_CREAT | os.O_WRONLY,
                              0o700), 'w') as fh:
                fh.write(cert.public_bytes(
                    serialization.Encoding.PEM).decode('utf-8'))
                fh.flush()
            key_filename = os.path.join(tmpdir, const.KEY_PEM)
            files_to_send.append(key_filename)
            with open(os.open(key_filename, os.O_CREAT | os.O_WRONLY,
                              0o700), 'w') as fh:
                fh.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()).decode(
                        'utf-8'))
                fh.flush()
            client_ca_filename = os.path.join(tmpdir, const.CLIENT_CA_PEM)
            files_to_send.append(client_ca_filename)
            with open(os.open(client_ca_filename, os.O_CREAT | os.O_WRONLY,
                              0o700), 'w') as fh:
                fh.write(cls.member_client_ca_cert.public_bytes(
                    serialization.Encoding.PEM).decode('utf-8'))
                fh.flush()

            # For security, we don't want to use a shell that can glob
            # the file names, so iterate over them.
            subprocess_args = {'stdout': subprocess.PIPE,
                               'stderr': subprocess.STDOUT,
                               'cwd': None}
            ssh_extra_args = (
                "-o PubkeyAcceptedKeyTypes=+ssh-rsa")
            if cls._need_scp_protocol():
                ssh_extra_args += " -O"
            cmd = ("scp -v -o UserKnownHostsFile=/dev/null "
                   "{9} "
                   "-o StrictHostKeyChecking=no "
                   "-o ConnectTimeout={0} -o ConnectionAttempts={1} "
                   "-i {2} {3} {4} {5} {6}@{7}:{8}").format(
                CONF.load_balancer.scp_connection_timeout,
                CONF.load_balancer.scp_connection_attempts,
                ssh_key.name, cert_filename, key_filename, client_ca_filename,
                CONF.validation.image_ssh_user, ip_address, const.DEV_SHM_PATH,
                ssh_extra_args)
            args = shlex.split(cmd)
            proc = subprocess.Popen(args, **subprocess_args)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                raise exceptions.CommandFailed(proc.returncode, cmd,
                                               stdout, stderr)
