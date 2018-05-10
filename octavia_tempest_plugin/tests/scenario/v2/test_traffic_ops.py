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

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
import testtools

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
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

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        listener_name = data_utils.rand_name("lb_member_listener1_operations")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '80',
            const.LOADBALANCER_ID: cls.lb_id,
        }
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)
        cls.listener_id = listener[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_listener_client.cleanup_listener,
            cls.listener_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_operations")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LISTENER_ID: cls.listener_id,
        }
        pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        cls.pool_id = pool[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_pool_client.cleanup_pool,
            cls.pool_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Traffic tests will not work in noop mode.')
    @decorators.idempotent_id('6751135d-e15a-4e22-89f4-bfcc3408d424')
    def test_basic_traffic(self):
        """Tests sending traffic through a loadbalancer

        * Create a fully populated loadbalancer.
        * Test traffic to ensure it is balanced properly.
        """
        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-traffic")
        member1_kwargs = {
            const.POOL_ID: self.pool_id,
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
            member1[const.ID], pool_id=self.pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-traffic")
        member2_kwargs = {
            const.POOL_ID: self.pool_id,
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
            member2[const.ID], pool_id=self.pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Send some traffic
        self._check_members_balanced(self.lb_vip_address)

    @decorators.idempotent_id('a16f8eb4-a77c-4b0e-8b1b-91c237039713')
    def test_healthmonitor_traffic(self):
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
            const.POOL_ID: self.pool_id,
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
            member1_id, pool_id=self.pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-hm-traffic")
        member2_kwargs = {
            const.POOL_ID: self.pool_id,
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
            member2_id, pool_id=self.pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 3 as a non-existent disabled node
        member3_name = data_utils.rand_name("lb_member_member3-hm-traffic")
        member3_kwargs = {
            const.POOL_ID: self.pool_id,
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
            member3_id, pool_id=self.pool_id,
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
            pool_id=self.pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_id)

        # Send some traffic and verify it is balanced
        self._check_members_balanced(self.lb_vip_address,
                                     traffic_member_count=2)

        # Create the healthmonitor
        hm_name = data_utils.rand_name("lb_member_hm1-hm-traffic")
        hm_kwargs = {
            const.POOL_ID: self.pool_id,
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
            pool_id=self.pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.ERROR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_id)

        # Send some traffic and verify it is *unbalanced*, as expected
        self._check_members_balanced(self.lb_vip_address,
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
            pool_id=self.pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member2_id, const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_id)
        waiters.wait_for_status(
            self.mem_member_client.show_member,
            member3_id, const.OPERATING_STATUS,
            const.OFFLINE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_id)

        # Send some traffic and verify it is balanced again
        self._check_members_balanced(self.lb_vip_address)
