# Copyright 2018 Rackspace, US Inc.
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class IPv6TrafficOperationsScenarioTest(
    test_base.LoadBalancerBaseTestWithCompute):
    """Test traffic operations with an IPv6 VIP."""

    @classmethod
    def skip_checks(cls):
        super(IPv6TrafficOperationsScenarioTest, cls).skip_checks()

        if not CONF.validation.run_validation:
            raise cls.skipException('Traffic tests will not work without '
                                    'run_validation enabled.')

        if CONF.load_balancer.test_with_noop:
            raise cls.skipException('Traffic tests will not work in noop '
                                    'mode.')

        if not CONF.load_balancer.test_with_ipv6:
            raise cls.skipException('IPv6 traffic ops tests require Octavia '
                                    'IPv6 testing enabled')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(IPv6TrafficOperationsScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_ipv6_ops")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        ip_version = 6
        cls._setup_lb_network_kwargs(lb_kwargs, ip_version)

        lb = cls.mem_lb_client.create_loadbalancer(**lb_kwargs)
        cls.lb_id = lb[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_lb_client.cleanup_loadbalancer,
            cls.lb_id)

        cls.lb_vip_address = lb[const.VIP_ADDRESS]

        # Per protocol listeners and pools IDs
        cls.listener_ids = {}
        cls.pool_ids = {}

        cls.protocol = const.HTTP
        lb_feature_enabled = CONF.loadbalancer_feature_enabled
        if not lb_feature_enabled.l7_protocol_enabled:
            cls.protocol = lb_feature_enabled.l4_protocol

        # Don't use same ports for HTTP/l4_protocol and UDP because some
        # releases (<=train) don't support it
        cls._listener_pool_create(const.HTTP, 80)

        cls._listener_pool_create(const.UDP, 8080)

    @classmethod
    def _listener_pool_create(cls, protocol, protocol_port):
        if (protocol == const.UDP and
                not cls.mem_listener_client.is_version_supported(
                    cls.api_version, '2.1')):
            return

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        listener_name = data_utils.rand_name("lb_member_listener1_ipv6_ops")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: cls.lb_id,
            # For branches that don't support multiple listeners in single
            # haproxy process and use haproxy>=1.8:
            const.CONNECTION_LIMIT: 200,
        }
        listener = cls.mem_listener_client.create_listener(
            **listener_kwargs)
        cls.listener_ids[protocol] = listener[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_listener_client.cleanup_listener,
            cls.listener_ids[protocol],
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_ipv6_ops")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: cls.lb_algorithm,
            const.LISTENER_ID: cls.listener_ids[protocol],
        }
        pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        cls.pool_ids[protocol] = pool[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_pool_client.cleanup_pool,
            cls.pool_ids[protocol],
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    def _test_ipv6_vip_mixed_ipv4_ipv6_members_traffic(self, protocol,
                                                       protocol_port):
        """Tests traffic through a loadbalancer with IPv4 and IPv6 members.

        * Set up members on a loadbalancer.
        * Test traffic to ensure it is balanced properly.
        """
        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-traffic")
        member1_kwargs = {
            const.POOL_ID: self.pool_ids[protocol],
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver1_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_1_subnet:
            member1_kwargs[const.SUBNET_ID] = self.lb_member_1_subnet[const.ID]

        member1 = self.mem_member_client.create_member(
            **member1_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member1[const.ID], pool_id=self.pool_ids[protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-traffic")
        member2_kwargs = {
            const.POOL_ID: self.pool_ids[protocol],
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ipv6,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_ipv6_subnet:
            member2_kwargs[const.SUBNET_ID] = (
                self.lb_member_2_ipv6_subnet[const.ID])

        member2 = self.mem_member_client.create_member(
            **member2_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=self.pool_ids[protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol)

    @decorators.idempotent_id('219ac17d-c5c1-4e7e-a9d5-0764d7ce7746')
    def test_ipv6_vip_mixed_ipv4_ipv6_members_traffic(self):
        self._test_ipv6_vip_mixed_ipv4_ipv6_members_traffic(self.protocol, 80)

    @decorators.idempotent_id('c468434d-bc84-4bfa-825f-d4761daa0d76')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_ipv6_vip_mixed_ipv4_ipv6_members_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')

        self._test_ipv6_vip_mixed_ipv4_ipv6_members_traffic(const.UDP, 8080)

    def _test_ipv6_vip_ipv6_members_traffic(self, protocol, protocol_port):
        """Tests traffic through a loadbalancer with IPv6 members.

        * Set up members on a loadbalancer.
        * Test traffic to ensure it is balanced properly.
        """

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-traffic")
        member1_kwargs = {
            const.POOL_ID: self.pool_ids[protocol],
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver1_ipv6,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_1_ipv6_subnet:
            member1_kwargs[const.SUBNET_ID] = (
                self.lb_member_1_ipv6_subnet[const.ID])

        member1 = self.mem_member_client.create_member(
            **member1_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member1[const.ID], pool_id=self.pool_ids[protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-traffic")
        member2_kwargs = {
            const.POOL_ID: self.pool_ids[protocol],
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ipv6,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_ipv6_subnet:
            member2_kwargs[const.SUBNET_ID] = (
                self.lb_member_2_ipv6_subnet[const.ID])

        member2 = self.mem_member_client.create_member(
            **member2_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=self.pool_ids[protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol)

    @decorators.idempotent_id('dd75f41a-5b29-47ad-963d-3434f1056ca3')
    def test_ipv6_vip_ipv6_members_traffic(self):
        self._test_ipv6_vip_ipv6_members_traffic(self.protocol, 80)

    @decorators.idempotent_id('26317013-a9b5-4a00-a993-d4c55b764e40')
    def test_ipv6_vip_ipv6_members_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')

        self._test_ipv6_vip_ipv6_members_traffic(const.UDP, 8080)
