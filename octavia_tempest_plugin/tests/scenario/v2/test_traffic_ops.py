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
import requests
import shlex
import testtools
import time

from oslo_log import log as logging
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import validators
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


@testtools.skipUnless(
    CONF.validation.run_validation,
    'Traffic tests will not work without run_validation enabled.')
class TrafficOperationsScenarioTest(test_base.LoadBalancerBaseTestWithCompute):

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
            cls.lb_id)

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

        # Per protocol listeners and pools IDs
        cls.listener_ids = {}
        cls.pool_ids = {}

        cls.protocol = const.HTTP
        lb_feature_enabled = CONF.loadbalancer_feature_enabled
        if not lb_feature_enabled.l7_protocol_enabled:
            cls.protocol = lb_feature_enabled.l4_protocol

        # Don't use same ports for HTTP/l4_protocol and UDP because some
        # releases (<=train) don't support it
        cls._listener_pool_create(cls.protocol, 80)

        cls._listener_pool_create(const.UDP, 8080)

    @classmethod
    def _listener_pool_create(cls, protocol, protocol_port):
        if (protocol == const.UDP and
                not cls.mem_listener_client.is_version_supported(
                    cls.api_version, '2.1')):
            return

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

        pool_name = data_utils.rand_name("lb_member_pool1_operations")
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

    def _test_basic_traffic(self, protocol, protocol_port):
        """Tests sending traffic through a loadbalancer

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
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

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

    @decorators.attr(type=['smoke', 'slow'])
    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('6751135d-e15a-4e22-89f4-bfcc3408d424')
    def test_basic_traffic(self):
        self._test_basic_traffic(self.protocol, 80)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('1e459663-2315-4067-bb47-c8a72f4928f0')
    def test_basic_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')

        self._test_basic_traffic(const.UDP, 8080)

    def _test_healthmonitor_traffic(self, protocol, protocol_port):
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
        member1_id = member1[const.ID]
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member1_id, pool_id=self.pool_ids[protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-hm-traffic")
        member2_kwargs = {
            const.POOL_ID: self.pool_ids[protocol],
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 80,
            const.MONITOR_PORT: 9999,  # We want this to go offline with a HM
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

        member2 = self.mem_member_client.create_member(
            **member2_kwargs)
        member2_id = member2[const.ID]
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2_id, pool_id=self.pool_ids[protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 3 as a non-existent disabled node
        member3_name = data_utils.rand_name("lb_member_member3-hm-traffic")
        member3_kwargs = {
            const.POOL_ID: self.pool_ids[protocol],
            const.NAME: member3_name,
            const.ADMIN_STATE_UP: False,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 80,
        }

        member3 = self.mem_member_client.create_member(
            **member3_kwargs)
        member3_id = member3[const.ID]
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member3_id, pool_id=self.pool_ids[protocol],
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
            pool_id=self.pool_ids[protocol])
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[protocol])
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[protocol])

        # Send some traffic and verify it is balanced
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol,
                                    traffic_member_count=2)

        # Create the healthmonitor
        hm_name = data_utils.rand_name("lb_member_hm1-hm-traffic")
        if protocol != const.HTTP:
            if protocol == const.UDP:
                hm_type = const.HEALTH_MONITOR_UDP_CONNECT
            elif protocol == const.TCP:
                hm_type = const.HEALTH_MONITOR_TCP

            hm_kwargs = {
                const.POOL_ID: self.pool_ids[protocol],
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
                const.POOL_ID: self.pool_ids[protocol],
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

        # Wait for members to adjust to the correct OPERATING_STATUS
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member1_id, const.OPERATING_STATUS,
            const.ONLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            error_ok=True,
            pool_id=self.pool_ids[protocol])
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.ERROR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[protocol])
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[protocol])

        # Send some traffic and verify it is *unbalanced*, as expected
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol,
                                    traffic_member_count=1)

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
            pool_id=self.pool_ids[protocol])
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[protocol])
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[protocol])

        # Send some traffic and verify it is balanced again
        self.check_members_balanced(self.lb_vip_address,
                                    protocol_port=protocol_port,
                                    protocol=protocol)

    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.health_monitor_enabled,
        'Health monitor testing is disabled')
    @decorators.idempotent_id('a16f8eb4-a77c-4b0e-8b1b-91c237039713')
    def test_healthmonitor_traffic(self):
        self._test_healthmonitor_traffic(self.protocol, 80)

    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.health_monitor_enabled,
        'Health monitor testing is disabled')
    @decorators.idempotent_id('80b86513-1a76-4e42-91c9-cb23c879e536')
    def test_healthmonitor_udp_traffic(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')

        self._test_healthmonitor_traffic(const.UDP, 8080)

    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.l7_protocol_enabled,
        'L7 protocol testing is disabled')
    @decorators.idempotent_id('3558186d-6dcd-4d9d-b7f7-adc190b66149')
    def test_l7policies_and_l7rules(self):
        """Tests sending traffic through a loadbalancer with l7rules

        * Create an extra pool.
        * Put one member on the default pool, and one on the second pool.
        * Create a policy/rule to redirect to the second pool.
        * Create a policy/rule to redirect to the identity URI.
        * Create a policy/rule to reject connections.
        * Test traffic to ensure it goes to the correct place.
        """
        protocol = const.HTTP

        # Create a second pool
        pool_name = data_utils.rand_name("lb_member_pool2_l7redirect")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: self.lb_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
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

        # Set up Member 1 for Webserver 1 on the default pool
        member1_name = data_utils.rand_name("lb_member_member1-l7redirect")
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

        # Set up Member 2 for Webserver 2 on the alternate pool
        member2_name = data_utils.rand_name("lb_member_member2-l7redirect")
        member2_kwargs = {
            const.POOL_ID: pool_id,
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
            member2[const.ID], pool_id=self.pool_ids[protocol],
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
            const.LISTENER_ID: self.listener_ids[protocol],
            const.NAME: l7policy1_name,
            const.DESCRIPTION: l7policy1_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
            const.ACTION: const.REDIRECT_TO_POOL,
            const.REDIRECT_POOL_ID: pool_id,
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
            const.LISTENER_ID: self.listener_ids[protocol],
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
            const.LISTENER_ID: self.listener_ids[protocol],
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
        url_for_member1 = 'http://{}/'.format(self.lb_vip_address)
        self.assertConsistentResponse((200, self.webserver1_response),
                                      url_for_member1)

        # Assert that slow traffic goes to pool2->member2
        url_for_member2 = 'http://{}/slow?delay=1s'.format(self.lb_vip_address)
        self.assertConsistentResponse((200, self.webserver2_response),
                                      url_for_member2)

        # Assert that /turtles is redirected to identity
        url_for_identity = 'http://{}/turtles'.format(self.lb_vip_address)
        self.assertConsistentResponse((302, CONF.identity.uri_v3),
                                      url_for_identity,
                                      redirect=True)

        # Assert that traffic with header 'reject=true' is rejected
        self.assertConsistentResponse((403, None),
                                      url_for_member1,
                                      headers={'reject': 'true'})

    def _test_mixed_ipv4_ipv6_members_traffic(self, protocol, protocol_port):
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

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'Mixed IPv4/IPv6 member test requires IPv6.')
    @decorators.idempotent_id('20b6b671-0101-4bed-a249-9af6ee3aa6d9')
    def test_mixed_ipv4_ipv6_members_traffic(self):
        self._test_mixed_ipv4_ipv6_members_traffic(self.protocol, 80)

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

        self._test_mixed_ipv4_ipv6_members_traffic(const.UDP, 8080)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Log offload tests will not work in noop mode.')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.log_offload_enabled,
        'Skipping log offload tests because tempest configuration '
        '[loadbalancer-feature-enabled] log_offload_enabled is False.')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.l7_protocol_enabled,
        'Log offload tests require l7_protocol_enabled.')
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
        validators.validate_URL_response(URL, expected_status_code=200)

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

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('13b0f2de-9934-457b-8be0-f1bffc6915a0')
    def test_listener_with_allowed_cidrs(self):
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
        listener_port = 8080
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: listener_port,
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
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool3_cidrs")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: self.lb_algorithm,
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
        self.check_members_balanced(
            self.lb_vip_address, protocol_port=listener_port)

        listener_kwargs = {
            const.LISTENER_ID: listener_id,
            const.ALLOWED_CIDRS: ['192.0.1.0/32']
        }
        self.mem_listener_client.update_listener(**listener_kwargs)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        url_for_vip = 'http://{}:{}/'.format(
            self.lb_vip_address, listener_port)

        # NOTE: Before we start with the consistent response check, we must
        # wait until Neutron completes the SG update.
        # See https://bugs.launchpad.net/neutron/+bug/1866353.
        def expect_conn_error(url):
            try:
                requests.Session().get(url)
            except requests.exceptions.ConnectionError:
                return True
            return False

        waiters.wait_until_true(expect_conn_error, url=url_for_vip)

        # Assert that the server is consistently unavailable
        self.assertConsistentResponse(
            (None, None), url_for_vip, repeat=3, conn_error=True)
