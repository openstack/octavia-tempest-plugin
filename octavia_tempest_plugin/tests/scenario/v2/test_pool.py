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


class PoolScenarioTest(test_base.LoadBalancerBaseTest):

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(PoolScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_pool")
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
        cls.protocol = const.HTTP
        lb_feature_enabled = CONF.loadbalancer_feature_enabled
        if not lb_feature_enabled.l7_protocol_enabled:
            cls.protocol = lb_feature_enabled.l4_protocol

        listener_name = data_utils.rand_name("lb_member_listener1_pool")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: cls.protocol,
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

    @decorators.idempotent_id('dfa120bf-81b9-4f22-bb5e-7df660c18173')
    def test_pool_standalone_CRUD(self):
        self._test_pool_CRUD(has_listener=False)

    @decorators.idempotent_id('087da8ab-79c7-48ba-871c-5769185cea3e')
    def test_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(has_listener=True)

    def _test_pool_CRUD(self, has_listener):
        """Tests pool create, read, update, delete

        * Create a fully populated pool.
        * Show pool details.
        * Update the pool.
        * Delete the pool.
        """
        # Pool create
        pool_name = data_utils.rand_name("lb_member_pool1-CRUD")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name,
            },
        }
        if has_listener:
            pool_kwargs[const.LISTENER_ID] = self.listener_id
        else:
            pool_kwargs[const.LOADBALANCER_ID] = self.lb_id

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool,
            pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        pool = waiters.wait_for_status(
            self.mem_pool_client.show_pool,
            pool[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(pool_name, pool[const.NAME])
        self.assertEqual(pool_description, pool[const.DESCRIPTION])
        self.assertFalse(pool[const.ADMIN_STATE_UP])
        parser.parse(pool[const.CREATED_AT])
        parser.parse(pool[const.UPDATED_AT])
        UUID(pool[const.ID])
        self.assertEqual(const.OFFLINE, pool[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        if has_listener:
            self.assertEqual(1, len(pool[const.LISTENERS]))
            self.assertEqual(self.listener_id,
                             pool[const.LISTENERS][0][const.ID])
        else:
            self.assertEmpty(pool[const.LISTENERS])
        self.assertEqual(const.LB_ALGORITHM_ROUND_ROBIN,
                         pool[const.LB_ALGORITHM])
        self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
        self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                         pool[const.SESSION_PERSISTENCE][const.TYPE])
        self.assertEqual(pool_sp_cookie_name,
                         pool[const.SESSION_PERSISTENCE][const.COOKIE_NAME])

        # Pool update
        new_name = data_utils.rand_name("lb_member_pool1-update")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        pool_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.LB_ALGORITHM: const.LB_ALGORITHM_LEAST_CONNECTIONS,
        }
        if self.protocol == const.HTTP:
            pool_update_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_HTTP_COOKIE}
        pool = self.mem_pool_client.update_pool(
            pool[const.ID], **pool_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        pool = waiters.wait_for_status(
            self.mem_pool_client.show_pool,
            pool[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(new_name, pool[const.NAME])
        self.assertEqual(new_description, pool[const.DESCRIPTION])
        self.assertTrue(pool[const.ADMIN_STATE_UP])
        self.assertEqual(const.LB_ALGORITHM_LEAST_CONNECTIONS,
                         pool[const.LB_ALGORITHM])
        self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
        if self.protocol == const.HTTP:
            self.assertEqual(const.SESSION_PERSISTENCE_HTTP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
        self.assertIsNone(
            pool[const.SESSION_PERSISTENCE].get(const.COOKIE_NAME))

        # Pool delete
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        self.mem_pool_client.delete_pool(pool[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_pool_client.show_pool, pool[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
