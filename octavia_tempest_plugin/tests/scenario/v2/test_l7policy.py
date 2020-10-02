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


class L7PolicyScenarioTest(test_base.LoadBalancerBaseTest):

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(L7PolicyScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_l7policy")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        cls._setup_lb_network_kwargs(lb_kwargs)

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

        listener_name = data_utils.rand_name("lb_member_listener1_l7policy")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '80',
            const.LOADBALANCER_ID: cls.lb_id,
        }
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)
        cls.listener_id = listener[const.ID]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_l7policy")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: cls.lb_id,
        }
        pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        cls.pool_id = pool[const.ID]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    @decorators.idempotent_id('ffd598d9-d8cd-4586-a749-cde4897e64dd')
    def test_l7policy_CRUD(self):
        """Tests l7policy create, read, update, delete

        * Create a fully populated l7policy.
        * Show l7policy details.
        * Update the l7policy.
        * Delete the l7policy.
        """

        # L7Policy create
        l7policy_name = data_utils.rand_name("lb_member_l7policy1-CRUD")
        l7policy_description = data_utils.arbitrary_string(size=255)
        l7policy_kwargs = {
            const.LISTENER_ID: self.listener_id,
            const.NAME: l7policy_name,
            const.DESCRIPTION: l7policy_description,
            const.ADMIN_STATE_UP: False,
            const.POSITION: 1,
            const.ACTION: const.REDIRECT_TO_POOL,
            const.REDIRECT_POOL_ID: self.pool_id,
        }

        l7policy = self.mem_l7policy_client.create_l7policy(**l7policy_kwargs)
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy,
            l7policy[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        l7policy = waiters.wait_for_status(
            self.mem_l7policy_client.show_l7policy,
            l7policy[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(l7policy_name, l7policy[const.NAME])
        self.assertEqual(l7policy_description, l7policy[const.DESCRIPTION])
        self.assertFalse(l7policy[const.ADMIN_STATE_UP])
        parser.parse(l7policy[const.CREATED_AT])
        parser.parse(l7policy[const.UPDATED_AT])
        UUID(l7policy[const.ID])
        # Operating status will be OFFLINE while admin_state_up = False
        self.assertEqual(const.OFFLINE, l7policy[const.OPERATING_STATUS])
        self.assertEqual(self.listener_id, l7policy[const.LISTENER_ID])
        self.assertEqual(1, l7policy[const.POSITION])
        self.assertEqual(const.REDIRECT_TO_POOL, l7policy[const.ACTION])
        self.assertEqual(self.pool_id, l7policy[const.REDIRECT_POOL_ID])
        self.assertIsNone(l7policy.pop(const.REDIRECT_URL, None))

        # L7Policy update
        new_name = data_utils.rand_name("lb_member_l7policy1-update")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        redirect_url = 'http://localhost'
        l7policy_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 2,
            const.ACTION: const.REDIRECT_TO_URL,
            const.REDIRECT_URL: redirect_url,
        }
        l7policy = self.mem_l7policy_client.update_l7policy(
            l7policy[const.ID], **l7policy_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        l7policy = waiters.wait_for_status(
            self.mem_l7policy_client.show_l7policy,
            l7policy[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(new_name, l7policy[const.NAME])
        self.assertEqual(new_description, l7policy[const.DESCRIPTION])
        self.assertTrue(l7policy[const.ADMIN_STATE_UP])
        # Operating status for a l7policy will be ONLINE if it is enabled:
        self.assertEqual(const.ONLINE, l7policy[const.OPERATING_STATUS])
        self.assertEqual(self.listener_id, l7policy[const.LISTENER_ID])
        # Position will have recalculated to 1
        self.assertEqual(1, l7policy[const.POSITION])
        self.assertEqual(const.REDIRECT_TO_URL, l7policy[const.ACTION])
        self.assertEqual(redirect_url, l7policy[const.REDIRECT_URL])
        self.assertIsNone(l7policy.pop(const.REDIRECT_POOL_ID, None))

        # L7Policy delete
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        self.mem_l7policy_client.delete_l7policy(l7policy[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_l7policy_client.show_l7policy, l7policy[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
