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

import time
from uuid import UUID

from dateutil import parser
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class L7RuleAPITest(test_base.LoadBalancerBaseTest):
    """Test the l7rule object API."""
    @classmethod
    def skip_checks(cls):
        super(L7RuleAPITest, cls).skip_checks()
        if not CONF.loadbalancer_feature_enabled.l7_protocol_enabled:
            raise cls.skipException(
                '[loadbalancer-feature-enabled] '
                '"l7_protocol_enabled" is set to False in the Tempest '
                'configuration. L7 API tests will be skipped.')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(L7RuleAPITest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_l7rule")
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

        listener_name = data_utils.rand_name("lb_member_listener1_l7rule")
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

        pool_name = data_utils.rand_name("lb_member_pool1_l7rule")
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

        l7policy_name = data_utils.rand_name("lb_member_l7policy1_l7rule")
        l7policy_kwargs = {
            const.NAME: l7policy_name,
            const.LISTENER_ID: cls.listener_id,
            const.ACTION: const.REJECT,
        }
        l7policy = cls.mem_l7policy_client.create_l7policy(**l7policy_kwargs)
        cls.l7policy_id = l7policy[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_l7policy_client.cleanup_l7policy,
            cls.l7policy_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    # Note: This test also covers basic l7rule show API
    @decorators.idempotent_id('55ac1337-189d-40a6-b614-47d7a8e991f6')
    def test_l7rule_create(self):
        """Tests l7rule create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create l7rules.
        * Create a fully populated l7rule.
        * Show l7rule details.
        * Validate the show reflects the requested values.
        """
        l7rule_kwargs = {
            const.ADMIN_STATE_UP: True,
            const.L7POLICY_ID: self.l7policy_id,
            const.TYPE: const.HEADER,
            const.VALUE: 'myvalue-create',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey-create',
            const.INVERT: False,
        }

        # Test that a user without the load balancer role cannot
        # create a l7rule
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.l7rule_client.create_l7rule,
                **l7rule_kwargs)

        l7rule = self.mem_l7rule_client.create_l7rule(**l7rule_kwargs)
        self.addClassResourceCleanup(
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
        if not CONF.load_balancer.test_with_noop:
            l7rule = waiters.wait_for_status(
                self.mem_l7rule_client.show_l7rule,
                l7rule[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout,
                l7policy_id=self.l7policy_id)

        parser.parse(l7rule[const.CREATED_AT])
        parser.parse(l7rule[const.UPDATED_AT])
        UUID(l7rule[const.ID])
        # Operating status for a l7rule will be ONLINE if it is enabled:
        if l7rule[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7rule[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7rule[const.OPERATING_STATUS])

        equal_items = [const.ADMIN_STATE_UP, const.TYPE, const.VALUE,
                       const.COMPARE_TYPE, const.KEY, const.INVERT]

        for item in equal_items:
            self.assertEqual(l7rule_kwargs[item], l7rule[item])

    @decorators.idempotent_id('69095254-f106-4fb6-9f54-7a78cc14fb51')
    def test_l7rule_list(self):
        """Tests l7rule list API and field filtering.

        * Create a clean l7policy.
        * Create three l7rules.
        * Validates that other accounts cannot list the l7rules.
        * List the l7rules using the default sort order.
        * List the l7rules using descending sort order.
        * List the l7rules using ascending sort order.
        * List the l7rules returning one field at a time.
        * List the l7rules returning two fields.
        * List the l7rules filtering to one of the three.
        * List the l7rules filtered, one field, and sorted.
        """
        l7policy_name = data_utils.rand_name("lb_member_l7policy2_l7rule-list")
        l7policy = self.mem_l7policy_client.create_l7policy(
            name=l7policy_name, listener_id=self.listener_id,
            action=const.REJECT)
        l7policy_id = l7policy[const.ID]
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy, l7policy_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        l7rule1_kwargs = {
            const.L7POLICY_ID: l7policy_id,
            const.ADMIN_STATE_UP: True,
            const.TYPE: const.HEADER,
            const.VALUE: '2',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey2-list',
        }
        l7rule1 = self.mem_l7rule_client.create_l7rule(
            **l7rule1_kwargs)
        self.addCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule1[const.ID], l7policy_id=l7policy_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        l7rule1 = waiters.wait_for_status(
            self.mem_l7rule_client.show_l7rule, l7rule1[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            l7policy_id=l7policy_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        l7rule2_kwargs = {
            const.L7POLICY_ID: l7policy_id,
            const.ADMIN_STATE_UP: True,
            const.TYPE: const.HEADER,
            const.VALUE: '1',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey1-list',
        }
        l7rule2 = self.mem_l7rule_client.create_l7rule(
            **l7rule2_kwargs)
        self.addCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule2[const.ID], l7policy_id=l7policy_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        l7rule2 = waiters.wait_for_status(
            self.mem_l7rule_client.show_l7rule, l7rule2[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            l7policy_id=l7policy_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        l7rule3_kwargs = {
            const.L7POLICY_ID: l7policy_id,
            const.ADMIN_STATE_UP: False,
            const.TYPE: const.HEADER,
            const.VALUE: '3',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey3-list',
        }
        l7rule3 = self.mem_l7rule_client.create_l7rule(
            **l7rule3_kwargs)
        self.addCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule3[const.ID], l7policy_id=l7policy_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        l7rule3 = waiters.wait_for_status(
            self.mem_l7rule_client.show_l7rule, l7rule3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            l7policy_id=l7policy_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)

        # Test that a different user cannot list l7rules
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.l7rule_client
            self.assertRaises(
                exceptions.Forbidden,
                member2_client.list_l7rules,
                l7policy_id)

        # Test that a user without the lb l7rule role cannot list load
        # balancers
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.l7rule_client.list_l7rules,
                l7policy_id)

        # Check the default sort order, created_at
        l7rules = self.mem_l7rule_client.list_l7rules(l7policy_id)
        self.assertEqual(l7rule1[const.VALUE],
                         l7rules[0][const.VALUE])
        self.assertEqual(l7rule2[const.VALUE],
                         l7rules[1][const.VALUE])
        self.assertEqual(l7rule3[const.VALUE],
                         l7rules[2][const.VALUE])

        # Test sort descending by `value`
        l7rules = self.mem_l7rule_client.list_l7rules(
            l7policy_id, query_params='{sort}={value}:{desc}'.format(
                sort=const.SORT, value=const.VALUE, desc=const.DESC))
        self.assertEqual(l7rule1[const.VALUE],
                         l7rules[1][const.VALUE])
        self.assertEqual(l7rule2[const.VALUE],
                         l7rules[2][const.VALUE])
        self.assertEqual(l7rule3[const.VALUE],
                         l7rules[0][const.VALUE])

        # Test sort ascending by `value`
        l7rules = self.mem_l7rule_client.list_l7rules(
            l7policy_id, query_params='{sort}={value}:{asc}'.format(
                sort=const.SORT, value=const.VALUE, asc=const.ASC))
        self.assertEqual(l7rule1[const.VALUE],
                         l7rules[1][const.VALUE])
        self.assertEqual(l7rule2[const.VALUE],
                         l7rules[0][const.VALUE])
        self.assertEqual(l7rule3[const.VALUE],
                         l7rules[2][const.VALUE])

        # Test fields
        for field in const.SHOW_L7RULE_RESPONSE_FIELDS:
            l7rules = self.mem_l7rule_client.list_l7rules(
                l7policy_id, query_params='{fields}={field}'.format(
                    fields=const.FIELDS, field=field))
            self.assertEqual(1, len(l7rules[0]))
            self.assertEqual(l7rule1[field], l7rules[0][field])
            self.assertEqual(l7rule2[field], l7rules[1][field])
            self.assertEqual(l7rule3[field], l7rules[2][field])

        # Test multiple fields at the same time
        l7rules = self.mem_l7rule_client.list_l7rules(
            l7policy_id,
            query_params='{fields}={admin}&{fields}={created}'.format(
                fields=const.FIELDS, admin=const.ADMIN_STATE_UP,
                created=const.CREATED_AT))
        self.assertEqual(2, len(l7rules[0]))
        self.assertTrue(l7rules[0][const.ADMIN_STATE_UP])
        parser.parse(l7rules[0][const.CREATED_AT])
        self.assertTrue(l7rules[1][const.ADMIN_STATE_UP])
        parser.parse(l7rules[1][const.CREATED_AT])
        self.assertFalse(l7rules[2][const.ADMIN_STATE_UP])
        parser.parse(l7rules[2][const.CREATED_AT])

        # Test filtering
        l7rules = self.mem_l7rule_client.list_l7rules(
            l7policy_id,
            query_params='{value}={rule_value}'.format(
                value=const.VALUE,
                rule_value=l7rule2[const.VALUE]))
        self.assertEqual(1, len(l7rules))
        self.assertEqual(l7rule2[const.VALUE],
                         l7rules[0][const.VALUE])

        # Test combined params
        l7rules = self.mem_l7rule_client.list_l7rules(
            l7policy_id,
            query_params='{admin}={true}&'
                         '{fields}={value}&{fields}={id}&'
                         '{sort}={value}:{desc}'.format(
                             admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, value=const.VALUE,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        # Should get two l7rules
        self.assertEqual(2, len(l7rules))
        # l7rules should have two fields
        self.assertEqual(2, len(l7rules[0]))
        # Should be in descending order by `value`
        self.assertEqual(l7rule2[const.VALUE],
                         l7rules[1][const.VALUE])
        self.assertEqual(l7rule1[const.VALUE],
                         l7rules[0][const.VALUE])

    @decorators.idempotent_id('b80b34c3-09fc-467b-8027-7350adb17070')
    def test_l7rule_show(self):
        """Tests l7rule show API.

        * Create a fully populated l7rule.
        * Show l7rule details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the l7rule.
        """
        l7rule_kwargs = {
            const.ADMIN_STATE_UP: True,
            const.L7POLICY_ID: self.l7policy_id,
            const.TYPE: const.HEADER,
            const.VALUE: 'myvalue-show',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey-show',
            const.INVERT: False,
        }

        l7rule = self.mem_l7rule_client.create_l7rule(**l7rule_kwargs)
        self.addClassResourceCleanup(
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
        if not CONF.load_balancer.test_with_noop:
            l7rule = waiters.wait_for_status(
                self.mem_l7rule_client.show_l7rule,
                l7rule[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout,
                l7policy_id=self.l7policy_id)

        parser.parse(l7rule[const.CREATED_AT])
        parser.parse(l7rule[const.UPDATED_AT])
        UUID(l7rule[const.ID])
        # Operating status for a l7rule will be ONLINE if it is enabled:
        if l7rule[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7rule[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7rule[const.OPERATING_STATUS])

        equal_items = [const.ADMIN_STATE_UP, const.TYPE, const.VALUE,
                       const.COMPARE_TYPE, const.KEY, const.INVERT]

        for item in equal_items:
            self.assertEqual(l7rule_kwargs[item], l7rule[item])

        # Test that a user with lb_admin role can see the l7rule
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            l7rule_client = self.os_roles_lb_admin.l7rule_client
            l7rule_adm = l7rule_client.show_l7rule(
                l7rule[const.ID], l7policy_id=self.l7policy_id)
            self.assertEqual(l7rule_kwargs[const.KEY], l7rule_adm[const.KEY])

        # Test that a user with cloud admin role can see the l7rule
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            adm = self.os_admin.l7rule_client.show_l7rule(
                l7rule[const.ID], l7policy_id=self.l7policy_id)
            self.assertEqual(l7rule_kwargs[const.KEY], adm[const.KEY])

        # Test that a different user, with load balancer member role, cannot
        # see this l7rule
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.l7rule_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.show_l7rule,
                              l7rule[const.ID], l7policy_id=self.l7policy_id)

        # Test that a user, without the load balancer member role, cannot
        # show l7rules
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.l7rule_client.show_l7rule,
                l7rule[const.ID], l7policy_id=self.l7policy_id)

    @decorators.idempotent_id('f8cee23b-89b6-4f3a-a842-1463daf42cf7')
    def test_l7rule_update(self):
        """Tests l7rule show API and field filtering.

        * Create a fully populated l7rule.
        * Show l7rule details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the l7rule.
        * Update the l7rule details.
        * Show l7rule details.
        * Validate the show reflects the initial values.
        """
        l7rule_kwargs = {
            const.ADMIN_STATE_UP: False,
            const.L7POLICY_ID: self.l7policy_id,
            const.TYPE: const.HEADER,
            const.VALUE: 'myvalue-update',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey-update',
            const.INVERT: False,
        }

        l7rule = self.mem_l7rule_client.create_l7rule(**l7rule_kwargs)
        self.addClassResourceCleanup(
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
        # Operating status for a l7rule will be ONLINE if it is enabled:
        if l7rule[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7rule[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7rule[const.OPERATING_STATUS])

        equal_items = [const.ADMIN_STATE_UP, const.TYPE, const.VALUE,
                       const.COMPARE_TYPE, const.KEY, const.INVERT]

        for item in equal_items:
            self.assertEqual(l7rule_kwargs[item], l7rule[item])

        # Test that a user, without the load balancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.l7rule_client.update_l7rule,
                l7rule[const.ID], l7policy_id=self.l7policy_id,
                admin_state_up=True)

        # Assert we didn't go into PENDING_*
        l7rule_check = self.mem_l7rule_client.show_l7rule(
            l7rule[const.ID], l7policy_id=self.l7policy_id)
        self.assertEqual(const.ACTIVE, l7rule_check[const.PROVISIONING_STATUS])
        self.assertEqual(False, l7rule_check[const.ADMIN_STATE_UP])

        # Test that a user, without the load balancer member role, cannot
        # update this l7rule
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.l7rule_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.update_l7rule,
                              l7rule[const.ID], l7policy_id=self.l7policy_id,
                              admin_state_up=True)

        # Assert we didn't go into PENDING_*
        l7rule_check = self.mem_l7rule_client.show_l7rule(
            l7rule[const.ID], l7policy_id=self.l7policy_id)
        self.assertEqual(const.ACTIVE, l7rule_check[const.PROVISIONING_STATUS])
        self.assertEqual(False, l7rule_check[const.ADMIN_STATE_UP])

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
        if l7rule[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7rule[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7rule[const.OPERATING_STATUS])

        # Test changed items (which is all of them, for l7rules)
        equal_items = [const.ADMIN_STATE_UP, const.TYPE, const.VALUE,
                       const.COMPARE_TYPE, const.KEY, const.INVERT]
        for item in equal_items:
            self.assertEqual(l7rule_update_kwargs[item], l7rule[item])

    @decorators.idempotent_id('8e15d68d-70e7-4cf3-82bc-9604384654a0')
    def test_l7rule_delete(self):
        """Tests l7rule create and delete APIs.

        * Creates a l7rule.
        * Validates that other accounts cannot delete the l7rule
        * Deletes the l7rule.
        * Validates the l7rule is in the DELETED state.
        """
        l7rule_kwargs = {
            const.L7POLICY_ID: self.l7policy_id,
            const.TYPE: const.HEADER,
            const.VALUE: 'myvalue-delete',
            const.COMPARE_TYPE: const.EQUAL_TO,
            const.KEY: 'mykey-delete',
        }
        l7rule = self.mem_l7rule_client.create_l7rule(**l7rule_kwargs)
        self.addClassResourceCleanup(
            self.mem_l7rule_client.cleanup_l7rule,
            l7rule[const.ID], l7policy_id=self.l7policy_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the load balancer role cannot
        # delete this l7rule
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.l7rule_client.delete_l7rule,
                l7rule[const.ID], l7policy_id=self.l7policy_id)

        # Test that a different user, with the load balancer member role
        # cannot delete this l7rule
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.l7rule_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.delete_l7rule,
                              l7rule[const.ID], l7policy_id=self.l7policy_id)

        self.mem_l7rule_client.delete_l7rule(l7rule[const.ID],
                                             l7policy_id=self.l7policy_id)

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_l7rule_client.show_l7rule, l7rule[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout,
            l7policy_id=self.l7policy_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
