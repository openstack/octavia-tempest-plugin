# Copyright 2018 GoDaddy
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

import datetime
import ipaddress
import shlex
import socket
import testtools
import time

from oslo_log import log as logging
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TrafficOperationsScenarioTest(test_base.LoadBalancerBaseTestWithCompute):

    @classmethod
    def skip_checks(cls):
        super().skip_checks()

        if not CONF.validation.run_validation:
            raise cls.skipException('Traffic tests will not work without '
                                    'run_validation enabled.')

        if CONF.load_balancer.test_with_noop:
            raise cls.skipException('Traffic tests will not work in noop '
                                    'mode.')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(TrafficOperationsScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_operations")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        # TODO(rm_work): Make this work with ipv6 and split this test for both
        ip_version = 4
        cls._setup_lb_network_kwargs(lb_kwargs, ip_version)

        lb = cls.mem_lb_client.create_loadbalancer(**lb_kwargs)
        cls.lb_id = lb[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_lb_client.cleanup_loadbalancer,
            cls.lb_id, cascade=True)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        if CONF.validation.connect_method == 'floating':
            port_id = lb[const.VIP_PORT_ID]
            result = cls.lb_mem_float_ip_client.create_floatingip(
                floating_network_id=CONF.network.public_network_id,
                port_id=port_id)
            floating_ip = result['floatingip']
            LOG.info('lb1_floating_ip: {}'.format(floating_ip))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_float_ip_client.delete_floatingip,
                cls.lb_mem_float_ip_client.show_floatingip,
                floatingip_id=floating_ip['id'])
            cls.lb_vip_address = floating_ip['floating_ip_address']
        else:
            cls.lb_vip_address = lb[const.VIP_ADDRESS]

    @classmethod
    def _listener_pool_create(cls, protocol, protocol_port,
                              pool_algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
                              insert_headers_dic=None):
        if (protocol == const.UDP and
                not cls.mem_listener_client.is_version_supported(
                    cls.api_version, '2.1')):
            return
        if (pool_algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            cls.mem_listener_client.is_version_supported(
                cls.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        listener_name = data_utils.rand_name("lb_member_listener1_operations")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: cls.lb_id,
            # For branches that don't support multiple listeners in single
            # haproxy process and use haproxy>=1.8:
            const.CONNECTION_LIMIT: 200,
        }

        if insert_headers_dic:
            listener_kwargs[const.INSERT_HEADERS] = insert_headers_dic

        listener = cls.mem_listener_client.create_listener(**listener_kwargs)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_operations")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LISTENER_ID: listener[const.ID],
        }
        pool = cls.mem_pool_client.create_pool(**pool_kwargs)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        return listener[const.ID], pool[const.ID]

    def _test_basic_traffic(
            self, protocol, protocol_port, pool_id, persistent=True,
            traffic_member_count=2, source_port=None, delay=None):
        """Tests sending traffic through a loadbalancer

        * Set up members on a loadbalancer.
        * Test traffic to ensure it is balanced properly.
        """
        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-traffic")
        member1_kwargs = {
            const.POOL_ID: pool_id,
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
            member1[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-traffic")
        member2_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

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
        self.check_members_balanced(
            self.lb_vip_address, protocol_port=protocol_port,
            persistent=persistent, protocol=protocol,
            traffic_member_count=traffic_member_count, source_port=source_port,
            delay=delay)

    def _pool_add_healthmonitor(self, pool_id, protocol):
        hm_name = data_utils.rand_name("lb_member_hm1-hm-traffic")
        if protocol != const.HTTP:
            if protocol == const.UDP:
                hm_type = const.HEALTH_MONITOR_UDP_CONNECT
            elif protocol == const.TCP:
                hm_type = const.HEALTH_MONITOR_TCP

            hm_kwargs = {
                const.POOL_ID: pool_id,
                const.NAME: hm_name,
                const.TYPE: hm_type,
                const.DELAY: 3,
                const.TIMEOUT: 2,
                const.MAX_RETRIES: 2,
                const.MAX_RETRIES_DOWN: 2,
                const.ADMIN_STATE_UP: True,
            }
        else:
            hm_kwargs = {
                const.POOL_ID: pool_id,
                const.NAME: hm_name,
                const.TYPE: const.HEALTH_MONITOR_HTTP,
                const.DELAY: 2,
                const.TIMEOUT: 2,
                const.MAX_RETRIES: 2,
                const.MAX_RETRIES_DOWN: 2,
                const.HTTP_METHOD: const.GET,
                const.URL_PATH: '/',
                const.EXPECTED_CODES: '200',
                const.ADMIN_STATE_UP: True,
            }
        hm = self.mem_healthmonitor_client.create_healthmonitor(**hm_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm[const.ID], lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        hm = waiters.wait_for_status(
            self.mem_healthmonitor_client.show_healthmonitor,
            hm[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        return hm

    @decorators.attr(type=['smoke', 'slow'])
    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('6751135d-e15a-4e22-89f4-bfcc3408d424')
    def test_basic_http_traffic(self):
        pool_id = self._listener_pool_create(const.HTTP, 80)[1]
        self._test_basic_traffic(const.HTTP, 80, pool_id)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('332a08e0-eff1-4c19-b46c-bf87148a6d84')
    def test_basic_tcp_traffic(self):
        pool_id = self._listener_pool_create(const.TCP, 81)[1]
        self._test_basic_traffic(const.TCP, 81, pool_id,
                                 persistent=False)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('1e459663-2315-4067-bb47-c8a72f4928f0')
    def test_basic_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(const.UDP, 8080)[1]
        self._test_basic_traffic(const.UDP, 8080, pool_id)

    def _test_healthmonitor_traffic(self, protocol, protocol_port,
                                    pool_id, persistent=True):
        """Tests traffic is correctly routed based on healthmonitor status

        * Create three members:
          * One should be working, and ONLINE with a healthmonitor (passing)
          * One should be working, and ERROR with a healthmonitor (failing)
          * One should be disabled, and OFFLINE with a healthmonitor
        * Verify members are in their correct respective operating statuses.
        * Verify that traffic is balanced evenly between the working members.
        * Create a fully populated healthmonitor.
        * Verify members are in their correct respective operating statuses.
        * Verify that traffic is balanced *unevenly*.
        * Delete the healthmonitor.
        * Verify members are in their correct respective operating statuses.
        * Verify that traffic is balanced evenly between the working members.
        """

        member1_name = data_utils.rand_name("lb_member_member1-hm-traffic")
        member1_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver1_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_1_subnet:
            member1_kwargs[const.SUBNET_ID] = self.lb_member_1_subnet[const.ID]

        member1 = self.mem_member_client.create_member(**member1_kwargs)
        member1_id = member1[const.ID]
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member1_id, pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-hm-traffic")
        member2_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 80,
            const.MONITOR_PORT: 9999,  # We want this to go offline with a HM
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

        member2 = self.mem_member_client.create_member(**member2_kwargs)
        member2_id = member2[const.ID]
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2_id, pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 3 as a non-existent disabled node
        member3_name = data_utils.rand_name("lb_member_member3-hm-traffic")
        member3_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member3_name,
            const.ADMIN_STATE_UP: False,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 80,
        }

        member3 = self.mem_member_client.create_member(**member3_kwargs)
        member3_id = member3[const.ID]
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member3_id, pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Wait for members to adjust to the correct OPERATING_STATUS
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member1_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)

        # Send some traffic and verify it is balanced
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol, persistent=persistent)

        # Create the healthmonitor
        hm = self._pool_add_healthmonitor(pool_id, protocol)

        # Wait for members to adjust to the correct OPERATING_STATUS
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member1_id, const.OPERATING_STATUS,
            const.ONLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            error_ok=True,
            pool_id=pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.ERROR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)

        # Send some traffic and verify it is *unbalanced*, as expected
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol,
                                    traffic_member_count=1,
                                    persistent=persistent)

        # Delete the healthmonitor
        self.mem_healthmonitor_client.delete_healthmonitor(hm[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_healthmonitor_client.show_healthmonitor, hm[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Wait for members to adjust to the correct OPERATING_STATUS
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member1_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)

        # Send some traffic and verify it is balanced again
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol, persistent=persistent)

    @decorators.idempotent_id('a16f8eb4-a77c-4b0e-8b1b-91c237039713')
    def test_healthmonitor_http_traffic(self):
        pool_id = self._listener_pool_create(const.HTTP, 82)[1]
        self._test_healthmonitor_traffic(const.HTTP, 82, pool_id)

    @decorators.idempotent_id('22f00c34-343b-4aa9-90be-4567ecf85772')
    def test_healthmonitor_tcp_traffic(self):
        pool_id = self._listener_pool_create(const.TCP, 83)[1]
        self._test_healthmonitor_traffic(const.TCP, 83, pool_id,
                                         persistent=False)

    @decorators.idempotent_id('80b86513-1a76-4e42-91c9-cb23c879e536')
    def test_healthmonitor_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')

        pool_id = self._listener_pool_create(const.UDP, 8081)[1]
        self._test_healthmonitor_traffic(const.UDP, 8081, pool_id)

    @decorators.idempotent_id('3558186d-6dcd-4d9d-b7f7-adc190b66149')
    def test_http_l7policies_and_l7rules(self):
        """Tests sending traffic through a loadbalancer with l7rules

        * Create an extra pool.
        * Put one member on the default pool, and one on the second pool.
        * Create a policy/rule to redirect to the second pool.
        * Create a policy/rule to redirect to the identity URI.
        * Create a policy/rule to reject connections.
        * Test traffic to ensure it goes to the correct place.
        """
        LISTENER_PORT = 84
        listener_id, pool_id = self._listener_pool_create(const.HTTP,
                                                          LISTENER_PORT)
        protocol = const.HTTP

        # Create a second pool
        pool_name = data_utils.rand_name("lb_member_pool2_l7redirect")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: self.lb_id,
        }
        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        pool2_id = pool[const.ID]
        self.addCleanup(
            self.mem_pool_client.cleanup_pool,
            pool2_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Set up Member 1 for Webserver 1 on the default pool
        member1_name = data_utils.rand_name("lb_member_member1-l7redirect")
        member1_kwargs = {
            const.POOL_ID: pool_id,
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
            member1[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2 on the alternate pool
        member2_name = data_utils.rand_name("lb_member_member2-l7redirect")
        member2_kwargs = {
            const.POOL_ID: pool2_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

        member2 = self.mem_member_client.create_member(
            **member2_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Create the l7policy to redirect to the alternate pool
        l7policy1_name = data_utils.rand_name("lb_member_l7policy1-l7redirect")
        l7policy1_description = data_utils.arbitrary_string(size=255)
        l7policy1_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy1_name,
            const.DESCRIPTION: l7policy1_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
            const.ACTION: const.REDIRECT_TO_POOL,
            const.REDIRECT_POOL_ID: pool2_id,
        }
        l7policy1 = self.mem_l7policy_client.create_l7policy(
            **l7policy1_kwargs)
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy,
            l7policy1[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Redirect slow queries to the alternate pool
        l7rule1_kwargs = {
            const.L7POLICY_ID: l7policy1[const.ID],
            const.ADMIN_STATE_UP: True,
            const.TYPE: const.PATH,
            const.VALUE: '/slow',
            const.COMPARE_TYPE: const.STARTS_WITH,
            const.INVERT: False,
        }

        l7rule1 = self.mem_l7rule_client.create_l7rule(**l7rule1_kwargs)
        self.addCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule1[const.ID], l7policy_id=l7rule1_kwargs[const.L7POLICY_ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Create the l7policy to redirect to the identity URI
        l7policy2_name = data_utils.rand_name("lb_member_l7policy2-l7redirect")
        l7policy2_description = data_utils.arbitrary_string(size=255)
        l7policy2_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy2_name,
            const.DESCRIPTION: l7policy2_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
            const.ACTION: const.REDIRECT_TO_URL,
            const.REDIRECT_URL: CONF.identity.uri_v3,
        }
        l7policy2 = self.mem_l7policy_client.create_l7policy(
            **l7policy2_kwargs)
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy,
            l7policy2[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Redirect queries for 'turtles' to identity
        l7rule2_kwargs = {
            const.L7POLICY_ID: l7policy2[const.ID],
            const.ADMIN_STATE_UP: True,
            const.TYPE: const.PATH,
            const.VALUE: '/turtles',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.INVERT: False,
        }

        l7rule2 = self.mem_l7rule_client.create_l7rule(**l7rule2_kwargs)
        self.addCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule2[const.ID], l7policy_id=l7rule2_kwargs[const.L7POLICY_ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Create the l7policy to reject requests
        l7policy3_name = data_utils.rand_name("lb_member_l7policy3-l7redirect")
        l7policy3_description = data_utils.arbitrary_string(size=255)
        l7policy3_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy3_name,
            const.DESCRIPTION: l7policy3_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
            const.ACTION: const.REJECT,
        }
        l7policy3 = self.mem_l7policy_client.create_l7policy(
            **l7policy3_kwargs)
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy,
            l7policy3[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Reject requests that include the header data 'reject=true'
        l7rule3_kwargs = {
            const.L7POLICY_ID: l7policy3[const.ID],
            const.ADMIN_STATE_UP: True,
            const.TYPE: const.HEADER,
            const.KEY: 'reject',
            const.VALUE: 'true',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.INVERT: False,
        }

        l7rule3 = self.mem_l7rule_client.create_l7rule(**l7rule3_kwargs)
        self.addCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule3[const.ID], l7policy_id=l7rule3_kwargs[const.L7POLICY_ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Assert that normal traffic goes to pool1->member1
        url_for_member1 = 'http://{}:{}/'.format(self.lb_vip_address,
                                                 LISTENER_PORT)
        self.assertConsistentResponse((200, self.webserver1_response),
                                      url_for_member1)

        # Assert that slow traffic goes to pool2->member2
        # Increase timeout to cope with slow test systems.
        url_for_member2 = 'http://{}:{}/slow?delay=1s'.format(
            self.lb_vip_address, LISTENER_PORT)
        self.assertConsistentResponse((200, self.webserver2_response),
                                      url_for_member2, timeout=3)

        # Assert that /turtles is redirected to identity
        url_for_identity = 'http://{}:{}/turtles'.format(self.lb_vip_address,
                                                         LISTENER_PORT)
        self.assertConsistentResponse((302, CONF.identity.uri_v3),
                                      url_for_identity,
                                      redirect=True)

        # Assert that traffic with header 'reject=true' is rejected
        self.assertConsistentResponse((403, None),
                                      url_for_member1,
                                      headers={'reject': 'true'})

    def _test_mixed_ipv4_ipv6_members_traffic(self, protocol, protocol_port,
                                              pool_id, persistent=True):
        """Tests traffic through a loadbalancer with IPv4 and IPv6 members.

        * Set up members on a loadbalancer.
        * Test traffic to ensure it is balanced properly.
        """

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-traffic")
        member1_kwargs = {
            const.POOL_ID: pool_id,
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
            member1[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-traffic")
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

        member2 = self.mem_member_client.create_member(
            **member2_kwargs)
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
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol, persistent=persistent)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'Mixed IPv4/IPv6 member test requires IPv6.')
    @decorators.idempotent_id('20b6b671-0101-4bed-a249-9af6ee3aa6d9')
    def test_mixed_ipv4_ipv6_members_http_traffic(self):
        pool_id = self._listener_pool_create(const.HTTP, 85)[1]
        self._test_mixed_ipv4_ipv6_members_traffic(const.HTTP, 85, pool_id)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'Mixed IPv4/IPv6 member test requires IPv6.')
    @decorators.idempotent_id('c442ae84-0abc-4470-8c7e-14a07e92a6fa')
    def test_mixed_ipv4_ipv6_members_tcp_traffic(self):
        pool_id = self._listener_pool_create(const.TCP, 86)[1]
        self._test_mixed_ipv4_ipv6_members_traffic(const.TCP, 86,
                                                   pool_id, persistent=False)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'Mixed IPv4/IPv6 member test requires IPv6.')
    @decorators.idempotent_id('56823616-34e1-4e17-beb9-15dd6b1593af')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_mixed_ipv4_ipv6_members_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(const.UDP, 8082)[1]
        self._test_mixed_ipv4_ipv6_members_traffic(const.UDP, 8082, pool_id)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('a58063fb-b9e8-4cfc-8a8c-7b2e9e884e7a')
    def test_least_connections_http_traffic(self):
        pool_id = self._listener_pool_create(
            const.HTTP, 87,
            pool_algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)[1]
        self._test_basic_traffic(const.HTTP, 87, pool_id)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('e1056709-6a1a-4a15-80c2-5cbb8279f924')
    def test_least_connections_tcp_traffic(self):
        pool_id = self._listener_pool_create(
            const.TCP, 88,
            pool_algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)[1]
        self._test_basic_traffic(const.TCP, 88, pool_id,
                                 persistent=False, delay=0.2)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('b5285410-507c-4629-90d4-6161540033d9')
    def test_least_connections_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(
            const.UDP, 8083,
            pool_algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)[1]
        self._test_basic_traffic(const.UDP, 8083, pool_id)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('881cc3e9-a011-4043-b0e3-a6185f736053')
    def test_source_ip_http_traffic(self):
        pool_id = self._listener_pool_create(
            const.HTTP, 89,
            pool_algorithm=const.LB_ALGORITHM_SOURCE_IP)[1]
        self._test_basic_traffic(const.HTTP, 89, pool_id,
                                 traffic_member_count=1, persistent=False)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('4568db0e-4243-4191-a822-9d327a55fa64')
    def test_source_ip_tcp_traffic(self):
        pool_id = self._listener_pool_create(
            const.TCP, 90, pool_algorithm=const.LB_ALGORITHM_SOURCE_IP)[1]
        self._test_basic_traffic(const.TCP, 90, pool_id,
                                 traffic_member_count=1, persistent=False)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('be9e6ef2-7840-47d7-9315-cdb1e897b202')
    def test_source_ip_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(
            const.UDP, 8084,
            pool_algorithm=const.LB_ALGORITHM_SOURCE_IP)[1]
        self._test_basic_traffic(const.UDP, 8084, pool_id,
                                 traffic_member_count=1, persistent=False)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('a446585b-5651-40ce-a4db-cb2ab4d37c03')
    def test_source_ip_port_http_traffic(self):
        # This is a special case as the reference driver does not support
        # this test. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool_id = self._listener_pool_create(
                const.HTTP, 60091,
                pool_algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)[1]
            self._test_basic_traffic(
                const.HTTP, 60091, pool_id,
                traffic_member_count=1, persistent=False, source_port=60091)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('60108f30-d870-487c-ab96-8d8a9b587b94')
    def test_source_ip_port_tcp_traffic(self):
        # This is a special case as the reference driver does not support
        # this test. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            listener_id, pool_id = self._listener_pool_create(
                const.TCP, 60092,
                pool_algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
            # Without a delay this can trigger a "Cannot assign requested
            # address" warning setting the source port, leading to failure
            self._test_basic_traffic(
                const.TCP, 60092, pool_id, traffic_member_count=1,
                persistent=False, source_port=60092, delay=0.2)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('a67dfa58-6953-4a0f-8a65-3f153b254c98')
    def test_source_ip_port_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        # This is a special case as the reference driver does not support
        # this test. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool_id = self._listener_pool_create(
                const.UDP, 8085,
                pool_algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)[1]
            self._test_basic_traffic(
                const.UDP, 8085, pool_id, traffic_member_count=1,
                persistent=False, source_port=8085)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Log offload tests will not work in noop mode.')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.log_offload_enabled,
        'Skipping log offload tests because tempest configuration '
        '[loadbalancer-feature-enabled] log_offload_enabled is False.')
    @decorators.idempotent_id('571dddd9-f5bd-404e-a799-9df7ac9e2fa9')
    def test_tenant_flow_log(self):
        """Tests tenant flow log offloading

        * Set up a member on a loadbalancer.
        * Sends a request to the load balancer.
        * Validates the flow log record for the request.
        """
        listener_name = data_utils.rand_name("lb_member_listener1_tenant_flow")
        protocol_port = '8123'
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
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

        pool_name = data_utils.rand_name("lb_member_pool1_tenant_flow")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_SOURCE_IP,
            const.LISTENER_ID: listener_id,
        }
        pool = self.mem_pool_client.create_pool(**pool_kwargs)
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

        # Set up Member for Webserver 1
        member_name = data_utils.rand_name("lb_member_member-tenant_flow")
        member_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver1_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_1_subnet:
            member_kwargs[const.SUBNET_ID] = self.lb_member_1_subnet[const.ID]

        member = self.mem_member_client.create_member(**member_kwargs)
        member_id = member[const.ID]
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        project_id = self.os_roles_lb_member.credentials.project_id
        unique_request_id = uuidutils.generate_uuid()
        LOG.info('Tenant flow logging unique request ID is: %s',
                 unique_request_id)

        # Make the request
        URL = 'http://{0}:{1}/{2}'.format(
            self.lb_vip_address, protocol_port, unique_request_id)
        self.validate_URL_response(URL, expected_status_code=200)

        # We need to give the log subsystem time to commit the log
        time.sleep(CONF.load_balancer.check_interval)

        # Get the tenant log entry
        log_line = None
        with open(CONF.load_balancer.tenant_flow_log_file) as f:
            for line in f:
                if unique_request_id in line:
                    log_line = line
                    break
        self.assertIsNotNone(
            log_line, 'Tenant log entry was not found in {0}.'.format(
                CONF.load_balancer.tenant_flow_log_file))

        # Remove the syslog prefix
        log_line = log_line[log_line.index(project_id):]

        # Split the line into the log format fields
        fields = shlex.split(log_line)

        # Validate the fields
        self.assertEqual(project_id, fields[0])  # project_id
        self.assertEqual(self.lb_id, fields[1])  # loadbalancer_id
        self.assertEqual(listener_id, fields[2])  # listener_id
        ipaddress.ip_address(fields[3])  # client_ip
        self.assertGreaterEqual(int(fields[4]), 0)  # client_port
        self.assertLessEqual(int(fields[4]), 65535)  # client_port
        datetime.datetime.strptime(fields[5],
                                   '%d/%b/%Y:%H:%M:%S.%f')  # date_time
        request_string = 'GET /{0} HTTP/1.1'.format(unique_request_id)
        self.assertEqual(request_string, fields[6])  # request_string
        self.assertEqual('200', fields[7])  # http_status
        self.assertTrue(fields[8].isdigit())  # bytes_read
        self.assertTrue(fields[9].isdigit())  # bytes_uploaded
        self.assertEqual('-', fields[10])  # client_cert_verify
        self.assertEqual("", fields[11])  # cert_dn
        pool_string = '{0}:{1}'.format(pool_id, listener_id)
        self.assertEqual(pool_string, fields[12])  # pool_id
        self.assertEqual(member_id, fields[13])  # member_id
        self.assertTrue(fields[14].isdigit())  # processing_time
        self.assertEqual('----', fields[15])  # term_state

    @decorators.idempotent_id('04399db0-04f0-4cb5-bb27-a12bf18bfe08')
    def test_http_LC_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 90, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('3d8d95b6-55e8-4bb9-b474-4ac35abaff22')
    def test_tcp_LC_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 91, const.LB_ALGORITHM_LEAST_CONNECTIONS, delay=0.2)

    @decorators.idempotent_id('7456b558-9add-4e0e-988e-06803f8047f7')
    def test_udp_LC_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 92, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('13b0f2de-9934-457b-8be0-f1bffc6915a0')
    def test_http_RR_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 93, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('8bca1325-f894-494d-95c6-3ea4c3df6a0b')
    def test_tcp_RR_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 94, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('93675cc3-e765-464b-9563-e0848dc75330')
    def test_udp_RR_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 95, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('fb5f35c1-08c9-43f7-8ed1-0395a3ef4735')
    def test_http_SI_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 96, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('c0904c88-2479-42e2-974f-55041f30e6c5')
    def test_tcp_SI_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 97, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('4f73bac5-2c98-45f9-8976-724c99e39979')
    def test_udp_SI_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 98, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('d198ddc5-1bcb-4310-a1b0-fa1a6328c4e9')
    def test_http_SIP_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.HTTP, 99, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('bbb09dbb-2aad-4281-9383-4bb4ad420ee1')
    def test_tcp_SIP_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.TCP, 100, const.LB_ALGORITHM_SOURCE_IP_PORT, delay=0.2)

    @decorators.idempotent_id('70290a9d-0065-42ad-bb46-884a535d2da2')
    def test_udp_SIP_listener_with_allowed_cidrs(self):
        self._test_listener_with_allowed_cidrs(
            const.UDP, 101, const.LB_ALGORITHM_SOURCE_IP_PORT, delay=0.2)

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
            const.ALLOWED_CIDRS: ['0.0.0.0/0']
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
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)

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
        except exceptions.NotImplemented as e:
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
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-cidrs-traffic")
        member1_kwargs = {
            const.POOL_ID: pool_id,
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
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

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
            const.ALLOWED_CIDRS: ['192.0.1.0/32']
        }
        self.mem_listener_client.update_listener(**listener_kwargs)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)

        # NOTE: Before we start with the consistent response check, we must
        # wait until Neutron completes the SG update.
        # See https://bugs.launchpad.net/neutron/+bug/1866353.
        def expect_timeout_error(address, protocol, protocol_port):
            try:
                self.make_request(address, protocol=protocol,
                                  protocol_port=protocol_port)
            except exceptions.TimeoutException:
                return True
            return False

        waiters.wait_until_true(
            expect_timeout_error, address=self.lb_vip_address,
            protocol=protocol, protocol_port=protocol_port)

        # Assert that the server is consistently unavailable
        if protocol == const.UDP:
            url_for_vip = 'udp://{}:{}/'.format(self.lb_vip_address,
                                                protocol_port)
        else:
            url_for_vip = 'http://{}:{}/'.format(self.lb_vip_address,
                                                 protocol_port)
        self.assertConsistentResponse(
            (None, None), url_for_vip, repeat=3, expect_connection_error=True)

    @decorators.idempotent_id('d3a28e76-76bc-11eb-a7c3-74e5f9e2a801')
    def test_insert_headers(self):
        # Create listener, enable insert of "X_FORWARDED_FOR" HTTP header
        listener_port = 102
        listener_id, pool_id = self._listener_pool_create(
            const.HTTP, listener_port, insert_headers_dic={
                const.X_FORWARDED_FOR: "true"})
        self._test_basic_traffic(
            const.HTTP, listener_port, pool_id)

        # Initiate HTTP traffic
        test_url = 'http://{}:{}/request'.format(
            self.lb_vip_address, listener_port)
        data = self.validate_URL_response(test_url)
        LOG.info('Received payload is: {}'.format(data))

        # Detect source IP that is used to create TCP socket toward LB_VIP.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.lb_vip_address, listener_port))
            client_source_ip = s.getsockname()[0]
            s.close()
        except Exception:
            LOG.exception('Failed to initiate TCP socket toward LB_VIP')
            raise Exception('LB_VIP is not available')

        # Function needed to parse the received payload from backend.
        # Returns dictionary of relevant headers if found.
        def _data_parser(payload, relevant_headers):
            retrieved_headers = {}
            for line in payload.split('\n'):
                try:
                    key, value = line.split(': ', 1)
                except ValueError:
                    continue
                if key in relevant_headers:
                    retrieved_headers[key] = value.lower()
            return retrieved_headers

        # Make sure that "X_FORWARDED_FOR" header was inserted with
        # expected IP (client_source_ip). Should present in data.
        expected_headers = {const.X_FORWARDED_FOR: client_source_ip}
        received_headers = _data_parser(data, expected_headers)
        self.assertEqual(expected_headers, received_headers)

        # Update listener to insert: "X_FORWARDED_PORT" and
        # "X_FORWARDED_PROTO"type headers.
        listener_kwargs = {
            const.LISTENER_ID: listener_id,
            const.INSERT_HEADERS: {
                const.X_FORWARDED_PORT: "true",
                const.X_FORWARDED_PROTO: "true"}}
        self.mem_listener_client.update_listener(**listener_kwargs)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)

        # Initiate HTTP traffic
        data = self.validate_URL_response(test_url)
        LOG.info('Received payload is: {}'.format(data))
        expected_headers = {const.X_FORWARDED_PORT: '{}'.format(
            listener_port), const.X_FORWARDED_PROTO: const.HTTP.lower()}
        received_headers = _data_parser(data, expected_headers)
        self.assertEqual(expected_headers, received_headers)

    @decorators.idempotent_id('2b05229c-0254-11eb-8610-74e5f9e2a801')
    def test_tcp_and_udp_traffic_on_same_port(self):
        common_vip_port = 103
        listener_id_udp, pool_id_udp = self._listener_pool_create(
            const.UDP, common_vip_port)
        listener_id_tcp, pool_id_tcp = self._listener_pool_create(
            const.TCP, common_vip_port)
        self._test_basic_traffic(const.UDP, common_vip_port, pool_id_udp)
        self._test_basic_traffic(const.TCP, common_vip_port, pool_id_tcp,
                                 persistent=False)

    @decorators.idempotent_id('c79f2cd0-0324-11eb-bc8e-74e5f9e2a801')
    def test_udp_update_pool_healthmonitor_listener(self):
        """Test scenario:

        * Prerequisites:
          Create: UDP listener, pool, healtmonitor and validate UDP traffic.
        * Test scenario:
          Update pool algorithm to: "source_ip" and start sending UDP traffic.
          Expected: successfully received UDP packages from LB VIP.
        * Update healtmonitor with: "delay=20" and start sending UDP traffic.
          Expected: successfully received UDP packages from LB VIP.
        * Update listener with: "connection-limit=300" and start sending
          UDP traffic.
          Expected: successfully received UDP packages from LB VIP.
        """
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        listener_port = 104
        listener_id, pool_id = self._listener_pool_create(
            const.UDP, listener_port)
        healthmonitor_id = self._pool_add_healthmonitor(
            pool_id, protocol=const.UDP)[const.ID]
        self._test_basic_traffic(
            const.UDP, listener_port, pool_id)

        # Update LB pool
        self.mem_pool_client.update_pool(
            pool_id=pool_id, lb_algorithm=const.LB_ALGORITHM_SOURCE_IP)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        self.assertIsNotNone(self.make_udp_requests_with_retries(
            vip_address=self.lb_vip_address, dst_port=listener_port,
            number_of_retries=3),
            'Failed - all UDP retries to LB VIP has failed')

        # Update LB healthmonitor
        self.mem_healthmonitor_client.update_healthmonitor(
            healthmonitor_id=healthmonitor_id, delay=5)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        self.assertIsNotNone(self.make_udp_requests_with_retries(
            vip_address=self.lb_vip_address, dst_port=listener_port,
            number_of_retries=3),
            'Failed - all UDP retries to LB VIP has failed')

        # Update LB listener
        listener_kwargs = {const.LISTENER_ID: listener_id,
                           const.CONNECTION_LIMIT: 300}
        self.mem_listener_client.update_listener(**listener_kwargs)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        self.assertIsNotNone(self.make_udp_requests_with_retries(
            vip_address=self.lb_vip_address, dst_port=listener_port,
            number_of_retries=3),
            'Failed - all UDP retries to LB VIP has failed')

    @decorators.attr(type='slow')
    @decorators.idempotent_id('cd5aeefa-0e16-11eb-b8dc-74e5f9e2a801')
    def test_hm_op_status_changed_as_expected_on_update(self):
        """Test scenario:

        * Create HTTP listener, pool and HTTP health monitor.
        * Update health monitor with various combinations of:
          HTTP method, expected HTTP status codes and backend URL.
          Note: see "fault_cases" and "valid_cases" lists in test's code.
        * Validate that members' operation status is getting into
          appropriate state after each particular update done within the test.
          Important: "operation status" value is expected to be changed from
          ONLINE to ERROR after each update, otherwise we may miss
          the potential bug.
        """
        listener_port = 105
        listener_id, pool_id = self._listener_pool_create(
            const.TCP, listener_port)
        hm_id = self._pool_add_healthmonitor(
            pool_id, protocol=const.HTTP)[const.ID]
        self._test_basic_traffic(
            const.HTTP, listener_port, pool_id, persistent=False)
        mb_ids = [mb[const.ID] for
                  mb in self.mem_member_client.list_members(pool_id)]

        # Create list of test cases to be covered in test
        fault_cases = [
            {'mthd': const.POST, 'code': '101-102', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=103'},
            {'mthd': const.DELETE, 'code': '201-204', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=205'},
            {'mthd': const.PUT, 'code': '301-302', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=303'},
            {'mthd': const.HEAD, 'code': '400-404', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=405'},
            {'mthd': const.OPTIONS, 'code': '500-504', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=505'},
            {'mthd': const.PATCH, 'code': '201-204', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=205'},
            {'mthd': const.CONNECT, 'code': '201-204', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=205'},
            {'mthd': const.TRACE, 'code': '201-204', 'op_stat': const.ERROR,
             'url_path': '/request?response_code=205'}]
        valid_cases = [
            {'mthd': const.GET, 'code': '101-102', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=102'},
            {'mthd': const.GET, 'code': '201-204', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=202'},
            {'mthd': const.GET, 'code': '301-302', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=302'},
            {'mthd': const.GET, 'code': '400-404', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=404'},
            {'mthd': const.GET, 'code': '500-504', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=504'},
            {'mthd': const.GET, 'code': '201-204', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=204'},
            {'mthd': const.GET, 'code': '201-204', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=204'},
            {'mthd': const.GET, 'code': '201-204', 'op_stat': const.ONLINE,
             'url_path': '/request?response_code=204'}]
        # Generate "flip_flop" using zip function, that will have
        # the operation statuses changed on each subsequent test case.
        # It means interleaved like: ERROR, ONLINE, ERROR, ONLINE...
        flip_flop = [v for f in zip(valid_cases, fault_cases) for v in f]

        # For each test case, update HM and validate that members'
        # "Operation Status" is changed to expected value.
        for ff in flip_flop:
            LOG.info('Tested test case is: {}'.format(ff))
            self.mem_healthmonitor_client.update_healthmonitor(
                hm_id, expected_codes=ff['code'], http_method=ff['mthd'],
                url_path=ff['url_path'])
            waiters.wait_for_status(
                self.mem_lb_client.show_loadbalancer, self.lb_id,
                const.PROVISIONING_STATUS, const.ACTIVE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)
            for mb_id in mb_ids:
                waiters.wait_for_status(
                    self.mem_member_client.show_member,
                    mb_id, const.OPERATING_STATUS,
                    ff['op_stat'],
                    CONF.load_balancer.check_interval,
                    CONF.load_balancer.check_timeout,
                    error_ok=True, pool_id=pool_id)
