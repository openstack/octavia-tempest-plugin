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


class L7RuleScenarioTest(test_base.LoadBalancerBaseTest):

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(L7RuleScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_l7rule")
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

        listener_name = data_utils.rand_name("lb_member_listener1_l7rule")
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

        l7policy_name = data_utils.rand_name("lb_member_l7policy1_l7rule")
        l7policy_kwargs = {
            const.NAME: l7policy_name,
            const.LISTENER_ID: cls.listener_id,
            const.ACTION: const.REJECT,
        }
        l7policy = cls.mem_l7policy_client.create_l7policy(**l7policy_kwargs)
        cls.l7policy_id = l7policy[const.ID]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    @decorators.idempotent_id('a1c268b9-5304-48c7-9a34-0ef0e8e9307e')
    def test_l7rule_CRUD(self):
        """Tests l7rule create, read, update, delete

        * Create a fully populated l7rule.
        * Show l7rule details.
        * Update the l7rule.
        * Delete the l7rule.
        """

        # L7Rule create
        l7rule_kwargs = {
            const.ADMIN_STATE_UP: False,
            const.L7POLICY_ID: self.l7policy_id,
            const.TYPE: const.HEADER,
            const.VALUE: 'myvalue-create',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey-create',
            const.INVERT: False,
        }

        l7rule = self.mem_l7rule_client.create_l7rule(**l7rule_kwargs)
        self.addCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule[const.ID], l7policy_id=self.l7policy_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        l7rule = waiters.wait_for_status(
            self.mem_l7rule_client.show_l7rule,
            l7rule[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            l7policy_id=self.l7policy_id)

        parser.parse(l7rule[const.CREATED_AT])
        parser.parse(l7rule[const.UPDATED_AT])
        UUID(l7rule[const.ID])
        # Operating status will be OFFLINE while admin_state_up = False
        self.assertEqual(const.OFFLINE, l7rule[const.OPERATING_STATUS])

        equal_items = [const.ADMIN_STATE_UP, const.TYPE, const.VALUE,
                       const.COMPARE_TYPE, const.KEY, const.INVERT]

        for item in equal_items:
            self.assertEqual(l7rule_kwargs[item], l7rule[item])

        # L7Rule update
        l7rule_update_kwargs = {
            const.L7POLICY_ID: self.l7policy_id,
            const.ADMIN_STATE_UP: True,
            const.TYPE: const.COOKIE,
            const.VALUE: 'myvalue-UPDATED',
            const.COMPARE_TYPE: const.CONTAINS,
            const.KEY: 'mykey-UPDATED',
            const.INVERT: True,
        }
        l7rule = self.mem_l7rule_client.update_l7rule(
            l7rule[const.ID], **l7rule_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        l7rule = waiters.wait_for_status(
            self.mem_l7rule_client.show_l7rule,
            l7rule[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            l7policy_id=self.l7policy_id)

        # Operating status for a l7rule will be ONLINE if it is enabled:
        self.assertEqual(const.ONLINE, l7rule[const.OPERATING_STATUS])

        # Test changed items (which is all of them, for l7rules)
        equal_items = [const.ADMIN_STATE_UP, const.TYPE, const.VALUE,
                       const.COMPARE_TYPE, const.KEY, const.INVERT]
        for item in equal_items:
            self.assertEqual(l7rule_update_kwargs[item], l7rule[item])

        # L7Rule delete
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        self.mem_l7rule_client.delete_l7rule(l7rule[const.ID],
                                             l7policy_id=self.l7policy_id)

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_l7rule_client.show_l7rule, l7rule[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout,
            l7policy_id=self.l7policy_id)
