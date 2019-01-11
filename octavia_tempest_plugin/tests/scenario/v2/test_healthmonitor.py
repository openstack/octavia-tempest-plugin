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

from uuid import UUID

from dateutil import parser
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class HealthMonitorScenarioTest(test_base.LoadBalancerBaseTest):

    @classmethod
    def skip_checks(cls):
        super(HealthMonitorScenarioTest, cls).skip_checks()
        if not CONF.loadbalancer_feature_enabled.health_monitor_enabled:
            raise cls.skipException('Health Monitors not supported')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(HealthMonitorScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_hm")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        cls._setup_lb_network_kwargs(lb_kwargs)

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

        pool_name = data_utils.rand_name("lb_member_pool1_hm")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: cls.lb_id,
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

    @decorators.idempotent_id('a51e09aa-6e44-4c67-a9e4-df70d0e08f96')
    def test_healthmonitor_CRUD(self):
        """Tests healthmonitor create, read, update, delete, and member status

        * Create a fully populated healthmonitor.
        * Show healthmonitor details.
        * Update the healthmonitor.
        * Delete the healthmonitor.
        """
        # Healthmonitor create
        hm_name = data_utils.rand_name("lb_member_hm1-CRUD")
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

        parser.parse(hm[const.CREATED_AT])
        parser.parse(hm[const.UPDATED_AT])
        UUID(hm[const.ID])
        self.assertEqual(const.ONLINE, hm[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.TYPE, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.HTTP_METHOD, const.URL_PATH, const.EXPECTED_CODES,
                       const.ADMIN_STATE_UP]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        # Healthmonitor update
        new_name = data_utils.rand_name("lb_member_hm1-update")
        hm_update_kwargs = {
            const.NAME: new_name,
            const.DELAY: hm_kwargs[const.DELAY] + 1,
            const.TIMEOUT: hm_kwargs[const.TIMEOUT] + 1,
            const.MAX_RETRIES: hm_kwargs[const.MAX_RETRIES] + 1,
            const.MAX_RETRIES_DOWN: hm_kwargs[const.MAX_RETRIES_DOWN] + 1,
            const.HTTP_METHOD: const.POST,
            const.URL_PATH: '/test',
            const.EXPECTED_CODES: '201,202',
            const.ADMIN_STATE_UP: not hm_kwargs[const.ADMIN_STATE_UP],
        }
        hm = self.mem_healthmonitor_client.update_healthmonitor(
            hm[const.ID], **hm_update_kwargs)

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

        # Test changed items
        equal_items = [const.NAME, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.HTTP_METHOD, const.URL_PATH, const.EXPECTED_CODES,
                       const.ADMIN_STATE_UP]

        for item in equal_items:
            self.assertEqual(hm_update_kwargs[item], hm[item])

        # Test unchanged items
        equal_items = [const.TYPE]
        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        # Healthmonitor delete
        self.mem_healthmonitor_client.delete_healthmonitor(hm[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_healthmonitor_client.show_healthmonitor, hm[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
