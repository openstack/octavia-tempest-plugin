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
import testtools

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

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
            cls.lb_id, cascade=True)

        cls.lb_vip_address = lb[const.VIP_ADDRESS]

        # Per protocol listeners and pools IDs
        cls.listener_ids = {}
        cls.pool_ids = {}

        # Don't use same ports for HTTP/l4_protocol and UDP because some
        # releases (<=train) don't support it
        cls._listener_pool_create(const.HTTP, 80)

        cls._listener_pool_create(const.TCP, 81)

        cls._listener_pool_create(const.UDP, 8080)

    @classmethod
    def _listener_pool_create(cls, protocol, protocol_port,
                              algorithm=const.LB_ALGORITHM_ROUND_ROBIN):
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
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)
        cls.listener_ids[protocol] = listener[const.ID]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_ipv6_ops")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: algorithm,
            const.LISTENER_ID: cls.listener_ids[protocol],
        }
        pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        cls.pool_ids[protocol] = pool[const.ID]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    def _test_ipv6_vip_mixed_ipv4_ipv6_members_traffic(
            self, protocol, protocol_port, persistent=True):
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

        member1 = self.mem_member_client.create_member(**member1_kwargs)
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

        member2 = self.mem_member_client.create_member(**member2_kwargs)
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
                                    protocol=protocol, persistent=persistent)

    @decorators.idempotent_id('219ac17d-c5c1-4e7e-a9d5-0764d7ce7746')
    def test_http_ipv6_vip_mixed_ipv4_ipv6_members_traffic(self):
        self._test_ipv6_vip_mixed_ipv4_ipv6_members_traffic(const.HTTP, 80)

    @decorators.idempotent_id('a4e8d5d1-03d5-4252-9300-e89b9b2bdafc')
    def test_tcp_ipv6_vip_mixed_ipv4_ipv6_members_traffic(self):
        self._test_ipv6_vip_mixed_ipv4_ipv6_members_traffic(const.TCP, 81,
                                                            persistent=False)

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

    def _test_ipv6_vip_ipv6_members_traffic(self, protocol, protocol_port,
                                            persistent=True):
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

        member1 = self.mem_member_client.create_member(**member1_kwargs)
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

        member2 = self.mem_member_client.create_member(**member2_kwargs)
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
                                    protocol=protocol, persistent=persistent)

    @decorators.idempotent_id('dd75f41a-5b29-47ad-963d-3434f1056ca3')
    def test_http_ipv6_vip_ipv6_members_traffic(self):
        self._test_ipv6_vip_ipv6_members_traffic(const.HTTP, 80)

    @decorators.idempotent_id('9bb93619-14cb-45d9-ad60-2f80c201486a')
    def test_tcp_ipv6_vip_ipv6_members_traffic(self):
        self._test_ipv6_vip_ipv6_members_traffic(const.TCP, 81,
                                                 persistent=False)

    @decorators.idempotent_id('26317013-a9b5-4a00-a993-d4c55b764e40')
    def test_ipv6_vip_ipv6_members_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')

        self._test_ipv6_vip_ipv6_members_traffic(const.UDP, 8080)

    @decorators.idempotent_id('9bead31b-0760-4c8f-b70a-f758fc5edd6a')
    def test_ipv6_http_LC_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 90, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('843a13f7-e00f-4151-8817-b5395eb69b52')
    def test_ipv6_tcp_LC_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 91, const.LB_ALGORITHM_LEAST_CONNECTIONS, delay=0.2)

    @decorators.idempotent_id('cc0d55b1-87e8-4a87-bf50-66299947a469')
    def test_ipv6_udp_LC_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 92, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('84b23f68-4bc3-49e5-8372-60c25fe69613')
    def test_ipv6_http_RR_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 93, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('52c07510-5755-44a3-9231-64c9cbb4bbd4')
    def test_ipv6_tcp_RR_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 94, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('df0417d9-dc72-4bb5-b3ce-1e2558a3c4a9')
    def test_ipv6_udp_RR_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 95, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('d1256195-3d85-4ffd-bda3-1c0ab78b8ce1')
    def test_ipv6_http_SI_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 96, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('bf8504b6-b95a-4f8a-9032-ab432db46eec')
    def test_ipv6_tcp_SI_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 97, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('ce75bf28-5288-4821-a603-460e602de8b9')
    def test_ipv6_udp_SI_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 98, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('c11768f1-19b4-48cc-99a5-0737379b1957')
    def test_ipv6_http_SIP_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 99, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('fcfe2ab1-2c36-4793-a926-1fec589a9a2a')
    def test_ipv6_tcp_SIP_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 100, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('80f31bc1-819e-4d9e-8820-bf3e28600540')
    def test_ipv6_udp_SIP_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 101, const.LB_ALGORITHM_SOURCE_IP_PORT)

    def _test_listener_with_allowed_cidrs(self, protocol, protocol_port,
                                          algorithm, delay=None):
        """Tests traffic through a loadbalancer with allowed CIDRs set.

        * Set up listener with allowed CIDRS (allow all) on a loadbalancer.
        * Set up pool on a loadbalancer
        * Set up members on a loadbalancer.
        * Test traffic to ensure it is balanced properly.
        * Update allowed CIDRs to restrict traffic to a small subnet.
        * Assert loadbalancer does not respond to client requests.
        """

        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            raise self.skipException('Allowed CIDRS in listeners is only '
                                     'available on Octavia API version 2.12 '
                                     'or newer.')

        listener_name = data_utils.rand_name("lb_member_listener2_cidrs")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.ALLOWED_CIDRS: ['::/0']
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        listener_id = listener[const.ID]
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool3_cidrs")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: algorithm,
            const.LISTENER_ID: listener_id,
        }
        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except tempest_exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        pool_id = pool[const.ID]
        self.addCleanup(
            self.mem_pool_client.cleanup_pool,
            pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-cidrs-traffic")
        member1_kwargs = {
            const.POOL_ID: pool_id,
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
            member1[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-cidrs-traffic")
        member2_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ipv6,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_ipv6_subnet:
            member2_kwargs[const.SUBNET_ID] = (
                self.lb_member_2_ipv6_subnet[const.ID])

        member2 = self.mem_member_client.create_member(**member2_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Send some traffic
        members = 2
        if algorithm == const.LB_ALGORITHM_SOURCE_IP:
            members = 1
        self.check_members_balanced(
            self.lb_vip_address, protocol=protocol,
            protocol_port=protocol_port, persistent=False,
            traffic_member_count=members, delay=delay)

        listener_kwargs = {
            const.LISTENER_ID: listener_id,
            const.ALLOWED_CIDRS: ['2001:db8:a0b:12f0::/128']
        }
        self.mem_listener_client.update_listener(**listener_kwargs)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # NOTE: Before we start with the consistent response check, we must
        # wait until Neutron completes the SG update.
        # See https://bugs.launchpad.net/neutron/+bug/1866353.
        def expect_timeout_error(address, protocol, protocol_port):
            if protocol != const.UDP:
                address = "[{}]".format(address)
            try:
                self.make_request(address, protocol=protocol,
                                  protocol_port=protocol_port)
            except tempest_exceptions.TimeoutException:
                return True
            return False

        waiters.wait_until_true(
            expect_timeout_error, address=self.lb_vip_address,
            protocol=protocol, protocol_port=protocol_port)

        # Assert that the server is consistently unavailable
        if protocol == const.UDP:
            url_for_vip = 'udp://[{}]:{}/'.format(self.lb_vip_address,
                                                  protocol_port)
        else:
            url_for_vip = 'http://[{}]:{}/'.format(self.lb_vip_address,
                                                   protocol_port)
        self.assertConsistentResponse(
            (None, None), url_for_vip, repeat=3, expect_connection_error=True)
