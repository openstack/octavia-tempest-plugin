# Copyright 2019 Red Hat Inc.  All rights reserved.
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

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class SparePoolTest(test_base.LoadBalancerBaseTestWithCompute):

    @classmethod
    def skip_checks(cls):
        super(SparePoolTest, cls).skip_checks()

        if CONF.load_balancer.provider not in const.AMPHORA_PROVIDERS:
            raise cls.skipException("Amphora tests require provider 'amphora' "
                                    "or 'octavia' (alias to 'amphora', "
                                    "deprecated) set")
        if not CONF.loadbalancer_feature_enabled.spare_pool_enabled:
            raise cls.skipException('[loadbalancer-feature-enabled] '
                                    '"spare_pool_enabled" is set to False in '
                                    'the Tempest configuration. Spare pool '
                                    'tests will be skipped.')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests"""
        super(SparePoolTest, cls).resource_setup()

    @decorators.idempotent_id('2ba3a2c2-de9d-4556-9535-cbe9209b4eaa')
    def test_health_manager_failover_to_spare_amp(self):
        """Tests Health Manager failover to amphora in spare pool.

        * Check amphora spare pool availability
        * Test the load balancer to make sure it is functioning
        * Delete amphora compute instance associated to load balancer
        * Validate load balancer fails over to spare amphora
        * Send traffic through load balancer
        * Validate amphora spare pool size is restored
        """
        amphora_client = self.os_admin.load_balancer_v2.AmphoraClient()
        # Check there is at least one amphora in spare pool
        spare_amps = waiters.wait_for_spare_amps(
            amphora_client.list_amphorae,
            CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)

        # Setup a load balancer for the tests to use
        lb_name = data_utils.rand_name("lb_spare_pool")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        self._setup_lb_network_kwargs(lb_kwargs, 4)

        lb = self.mem_lb_client.create_loadbalancer(**lb_kwargs)
        self.lb_id = lb[const.ID]
        self.addClassResourceCleanup(self.mem_lb_client.cleanup_loadbalancer,
                                     self.lb_id, cascade=True)

        if CONF.validation.connect_method == 'floating':
            port_id = lb[const.VIP_PORT_ID]
            result = self.lb_mem_float_ip_client.create_floatingip(
                floating_network_id=CONF.network.public_network_id,
                port_id=port_id)
            floating_ip = result['floatingip']
            LOG.info('lb1_floating_ip: {}'.format(floating_ip))
            self.addClassResourceCleanup(
                waiters.wait_for_not_found,
                self.lb_mem_float_ip_client.delete_floatingip,
                self.lb_mem_float_ip_client.show_floatingip,
                floatingip_id=floating_ip['id'])
            self.lb_vip_address = floating_ip['floating_ip_address']
        else:
            self.lb_vip_address = lb[const.VIP_ADDRESS]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        # Confirm the spare pool has changed since last check
        spare_amps_2 = waiters.wait_for_spare_amps(
            amphora_client.list_amphorae,
            CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)
        self.assertNotEqual(spare_amps, spare_amps_2)

        listener_name = data_utils.rand_name("lb_member_listener1_spare")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '80',
            const.LOADBALANCER_ID: self.lb_id,
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.listener_id = listener[const.ID]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1-spare")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: self.lb_algorithm,
            const.LISTENER_ID: self.listener_id,
        }
        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.pool_id = pool[const.ID]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-spare")
        member1_kwargs = {
            const.POOL_ID: self.pool_id,
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver1_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_1_subnet:
            member1_kwargs[const.SUBNET_ID] = self.lb_member_1_subnet[const.ID]

        self.mem_member_client.create_member(**member1_kwargs)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-spare")
        member2_kwargs = {
            const.POOL_ID: self.pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 80,
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

        self.mem_member_client.create_member(**member2_kwargs)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address)

        # Check there is at least one amphora in spare pool
        spare_amps = waiters.wait_for_spare_amps(
            amphora_client.list_amphorae,
            CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)

        # Delete amphora compute instance
        amp = amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))

        self.os_admin_servers_client.delete_server(amp[0][const.COMPUTE_ID])

        # Wait for the amphora failover to start
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.PENDING_UPDATE, CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Wait for the load balancer to return to ACTIVE so the
        # cleanup steps will pass
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE, CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address)

        # Confirm the spare pool has changed since last check
        spare_amps_2 = waiters.wait_for_spare_amps(
            amphora_client.list_amphorae,
            CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)
        self.assertNotEqual(spare_amps, spare_amps_2)

        # Check there is at least one amphora in spare pool
        waiters.wait_for_spare_amps(amphora_client.list_amphorae,
                                    CONF.load_balancer.lb_build_interval,
                                    CONF.load_balancer.lb_build_timeout)
