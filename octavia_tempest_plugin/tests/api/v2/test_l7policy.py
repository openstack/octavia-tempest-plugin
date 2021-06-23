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

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class L7PolicyAPITest(test_base.LoadBalancerBaseTest):
    """Test the l7policy object API."""
    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(L7PolicyAPITest, cls).resource_setup()

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

    @decorators.idempotent_id('eba4ddc2-758b-4dd5-bd28-c1b41d6575ca')
    def test_l7policy_create_redirect_pool(self):
        self._test_l7policy_create(pool_id=self.pool_id)

    @decorators.idempotent_id('2b529135-71bc-46f7-912f-74d238d67190')
    def test_l7policy_create_redirect_url(self):
        self._test_l7policy_create(url='http://localhost')

    @decorators.idempotent_id('aa9b0d50-0d16-4365-85eb-846b17eb8398')
    def test_l7policy_create_reject(self):
        self._test_l7policy_create()

    def _test_l7policy_create(self, url=None, pool_id=None):
        """Tests l7policy create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create l7policies.
        * Create a fully populated l7policy.
        * Show l7policy details.
        * Validate the show reflects the requested values.
        """
        l7policy_name = data_utils.rand_name("lb_member_l7policy1-create")
        l7policy_description = data_utils.arbitrary_string(size=255)
        l7policy_kwargs = {
            const.LISTENER_ID: self.listener_id,
            const.NAME: l7policy_name,
            const.DESCRIPTION: l7policy_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
        }

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            l7_policy_tags = ["Hello", "World"]
            l7policy_kwargs.update({
                const.TAGS: l7_policy_tags
            })

        if url:
            l7policy_kwargs[const.ACTION] = const.REDIRECT_TO_URL
            l7policy_kwargs[const.REDIRECT_URL] = url
        elif pool_id:
            l7policy_kwargs[const.ACTION] = const.REDIRECT_TO_POOL
            l7policy_kwargs[const.REDIRECT_POOL_ID] = pool_id
        else:
            l7policy_kwargs[const.ACTION] = const.REJECT

        # Test that a user without the load balancer role cannot
        # create a l7policy
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'L7PolicyClient', 'create_l7policy',
                expected_allowed,
                status_method=self.mem_lb_client.show_loadbalancer,
                obj_id=self.lb_id, **l7policy_kwargs)

        l7policy = self.mem_l7policy_client.create_l7policy(**l7policy_kwargs)

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
        if not CONF.load_balancer.test_with_noop:
            l7policy = waiters.wait_for_status(
                self.mem_l7policy_client.show_l7policy,
                l7policy[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(l7policy_name, l7policy[const.NAME])
        self.assertEqual(l7policy_description, l7policy[const.DESCRIPTION])
        self.assertTrue(l7policy[const.ADMIN_STATE_UP])
        parser.parse(l7policy[const.CREATED_AT])
        parser.parse(l7policy[const.UPDATED_AT])
        UUID(l7policy[const.ID])
        # Operating status for a l7policy will be ONLINE if it is enabled:
        if l7policy[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7policy[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7policy[const.OPERATING_STATUS])
        self.assertEqual(self.listener_id, l7policy[const.LISTENER_ID])
        self.assertEqual(1, l7policy[const.POSITION])
        if url:
            self.assertEqual(const.REDIRECT_TO_URL, l7policy[const.ACTION])
            self.assertEqual(url, l7policy[const.REDIRECT_URL])
            self.assertIsNone(l7policy.pop(const.REDIRECT_POOL_ID, None))
        elif pool_id:
            self.assertEqual(const.REDIRECT_TO_POOL, l7policy[const.ACTION])
            self.assertEqual(pool_id, l7policy[const.REDIRECT_POOL_ID])
            self.assertIsNone(l7policy.pop(const.REDIRECT_URL, None))
        else:
            self.assertEqual(const.REJECT, l7policy[const.ACTION])
            self.assertIsNone(l7policy.pop(const.REDIRECT_URL, None))
            self.assertIsNone(l7policy.pop(const.REDIRECT_POOL_ID, None))

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(l7policy_kwargs[const.TAGS],
                                  l7policy[const.TAGS])

    @decorators.idempotent_id('42fa14ba-caf1-465e-ab36-27e7501f95ef')
    def test_l7policy_list(self):
        """Tests l7policy list API and field filtering.

        * Create a clean listener.
        * Create three l7policies.
        * Validates that other accounts cannot list the l7policies.
        * List the l7policies using the default sort order.
        * List the l7policies using descending sort order.
        * List the l7policies using ascending sort order.
        * List the l7policies returning one field at a time.
        * List the l7policies returning two fields.
        * List the l7policies filtering to one of the three.
        * List the l7policies filtered, one field, and sorted.
        """
        # IDs of L7 policies created in the test
        test_ids = []

        listener_name = data_utils.rand_name(
            "lb_member_listener2_l7policy-list")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '81',
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

        l7policy1_name = data_utils.rand_name("lb_member_l7policy2-list")
        l7policy1_desc = 'B'
        l7policy1_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy1_name,
            const.DESCRIPTION: l7policy1_desc,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
            const.ACTION: const.REJECT
        }

        if self.mem_l7policy_client.is_version_supported(
                self.api_version, '2.5'):
            l7policy1_tags = ["English", "Mathematics",
                              "Marketing", "Creativity"]
            l7policy1_kwargs.update({const.TAGS: l7policy1_tags})

        l7policy1 = self.mem_l7policy_client.create_l7policy(
            **l7policy1_kwargs)
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy,
            l7policy1[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        l7policy1 = waiters.wait_for_status(
            self.mem_l7policy_client.show_l7policy, l7policy1[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(l7policy1[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        l7policy2_name = data_utils.rand_name("lb_member_l7policy1-list")
        l7policy2_desc = 'A'
        l7policy2_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy2_name,
            const.DESCRIPTION: l7policy2_desc,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
            const.ACTION: const.REDIRECT_TO_POOL,
            const.REDIRECT_POOL_ID: self.pool_id
        }

        if self.mem_l7policy_client.is_version_supported(
                self.api_version, '2.5'):
            l7policy2_tags = ["English", "Spanish",
                              "Soft_skills", "Creativity"]
            l7policy2_kwargs.update({const.TAGS: l7policy2_tags})

        l7policy2 = self.mem_l7policy_client.create_l7policy(
            **l7policy2_kwargs)
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy,
            l7policy2[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        l7policy2 = waiters.wait_for_status(
            self.mem_l7policy_client.show_l7policy, l7policy2[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(l7policy2[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        l7policy3_name = data_utils.rand_name("lb_member_l7policy3-list")
        l7policy3_desc = 'C'
        l7_redirect_url = 'http://localhost'
        l7policy3_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy3_name,
            const.DESCRIPTION: l7policy3_desc,
            const.ADMIN_STATE_UP: False,
            const.POSITION: 1,
            const.ACTION: const.REDIRECT_TO_URL,
            const.REDIRECT_URL: l7_redirect_url
        }

        if self.mem_l7policy_client.is_version_supported(
                self.api_version, '2.5'):
            l7policy3_tags = ["English", "Project_management",
                              "Communication", "Creativity"]
            l7policy3_kwargs.update({const.TAGS: l7policy3_tags})

        l7policy3 = self.mem_l7policy_client.create_l7policy(
            **l7policy3_kwargs)
        self.addCleanup(
            self.mem_l7policy_client.cleanup_l7policy,
            l7policy3[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        l7policy3 = waiters.wait_for_status(
            self.mem_l7policy_client.show_l7policy, l7policy3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(l7policy3[const.ID])

        # Test that a different users cannot see the lb_member l7policies
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_primary', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_primary',
                                'os_roles_lb_member2', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_roles_lb_observer', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_list_RBAC_enforcement_count(
                'L7PolicyClient', 'list_l7policies',
                expected_allowed, 0)

        # Test credentials that should see these l7policies can see them.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin', 'os_roles_lb_member',
                                'os_roles_lb_global_observer']
        if expected_allowed:
            self.check_list_IDs_RBAC_enforcement(
                'L7PolicyClient', 'list_l7policies',
                expected_allowed, test_ids,
                query_params='listener_id={listener_id}'.format(
                    listener_id=listener_id))

        # Test that users without the lb member role cannot list l7policies
        # Note: non-owners can still call this API, they will just get the list
        #       of L7 policies for their project (zero). The above tests
        #       are intended to cover the cross project use case.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_primary', 'os_roles_lb_admin',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        # Note: os_admin is here because it evaluaties to "project_admin"
        #       in oslo_policy and since keystone considers "project_admin"
        #       a superscope of "project_reader". This means it can read
        #       objects in the "admin" credential's project.
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_primary', 'os_system_admin',
                                'os_system_reader', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'L7PolicyClient', 'list_l7policies',
                expected_allowed)

        # Check the default sort order, created_at
        l7policies = self.mem_l7policy_client.list_l7policies(
            query_params='listener_id={listener_id}'.format(
                listener_id=listener_id))
        self.assertEqual(l7policy1[const.DESCRIPTION],
                         l7policies[0][const.DESCRIPTION])
        self.assertEqual(l7policy2[const.DESCRIPTION],
                         l7policies[1][const.DESCRIPTION])
        self.assertEqual(l7policy3[const.DESCRIPTION],
                         l7policies[2][const.DESCRIPTION])

        # Test sort descending by description
        l7policies = self.mem_l7policy_client.list_l7policies(
            query_params='listener_id={listener_id}&{sort}={descr}:{desc}'
                         .format(listener_id=listener_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, desc=const.DESC))
        self.assertEqual(l7policy1[const.DESCRIPTION],
                         l7policies[1][const.DESCRIPTION])
        self.assertEqual(l7policy2[const.DESCRIPTION],
                         l7policies[2][const.DESCRIPTION])
        self.assertEqual(l7policy3[const.DESCRIPTION],
                         l7policies[0][const.DESCRIPTION])

        # Test sort ascending by description
        l7policies = self.mem_l7policy_client.list_l7policies(
            query_params='listener_id={listener_id}&{sort}={descr}:{asc}'
                         .format(listener_id=listener_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, asc=const.ASC))
        self.assertEqual(l7policy1[const.DESCRIPTION],
                         l7policies[1][const.DESCRIPTION])
        self.assertEqual(l7policy2[const.DESCRIPTION],
                         l7policies[0][const.DESCRIPTION])
        self.assertEqual(l7policy3[const.DESCRIPTION],
                         l7policies[2][const.DESCRIPTION])

        # Use this opportunity to verify the position insertion is working
        l7policies = self.mem_l7policy_client.list_l7policies(
            query_params='listener_id={listener_id}&{sort}={position}:{asc}'
                         .format(listener_id=listener_id, sort=const.SORT,
                                 position=const.POSITION, asc=const.ASC))
        self.assertEqual(1, l7policies[0][const.POSITION])
        self.assertEqual(2, l7policies[1][const.POSITION])
        self.assertEqual(3, l7policies[2][const.POSITION])
        self.assertEqual(l7policy1[const.NAME],
                         l7policies[2][const.NAME])
        self.assertEqual(l7policy2[const.NAME],
                         l7policies[1][const.NAME])
        self.assertEqual(l7policy3[const.NAME],
                         l7policies[0][const.NAME])

        # Test fields
        for field in const.SHOW_L7POLICY_RESPONSE_FIELDS:
            # Test position / updated fields separately, because they're odd
            if field not in (const.POSITION, const.UPDATED_AT):
                l7policies = self.mem_l7policy_client.list_l7policies(
                    query_params='listener_id={listener_id}&{fields}={field}'
                                 .format(listener_id=listener_id,
                                         fields=const.FIELDS, field=field))
                self.assertEqual(1, len(l7policies[0]))
                self.assertEqual(l7policy1[field], l7policies[0][field])
                self.assertEqual(l7policy2[field], l7policies[1][field])
                self.assertEqual(l7policy3[field], l7policies[2][field])
            elif field == const.POSITION:
                l7policies = self.mem_l7policy_client.list_l7policies(
                    query_params='listener_id={listener_id}&{fields}={field}'
                                 .format(listener_id=listener_id,
                                         fields=const.FIELDS, field=field))
                self.assertEqual(1, len(l7policies[0]))
                # Positions won't match the request due to insertion reordering
                self.assertEqual(3, l7policies[0][field])
                self.assertEqual(2, l7policies[1][field])
                self.assertEqual(1, l7policies[2][field])
            elif field == const.UPDATED_AT:
                l7policies = self.mem_l7policy_client.list_l7policies(
                    query_params='listener_id={listener_id}&{fields}={field}'
                                 .format(listener_id=listener_id,
                                         fields=const.FIELDS, field=field))
                # Just test that we get it -- the actual value is unpredictable
                self.assertEqual(1, len(l7policies[0]))

        # Test multiple fields at the same time
        l7policies = self.mem_l7policy_client.list_l7policies(
            query_params='listener_id={listener_id}&{fields}={admin}&'
                         '{fields}={created}'.format(
                             listener_id=listener_id, fields=const.FIELDS,
                             admin=const.ADMIN_STATE_UP,
                             created=const.CREATED_AT))
        self.assertEqual(2, len(l7policies[0]))
        self.assertTrue(l7policies[0][const.ADMIN_STATE_UP])
        parser.parse(l7policies[0][const.CREATED_AT])
        self.assertTrue(l7policies[1][const.ADMIN_STATE_UP])
        parser.parse(l7policies[1][const.CREATED_AT])
        self.assertFalse(l7policies[2][const.ADMIN_STATE_UP])
        parser.parse(l7policies[2][const.CREATED_AT])

        # Test filtering
        l7policies = self.mem_l7policy_client.list_l7policies(
            query_params='listener_id={listener_id}&'
                         '{desc}={l7policy_desc}'.format(
                             listener_id=listener_id, desc=const.DESCRIPTION,
                             l7policy_desc=l7policy2[const.DESCRIPTION]))
        self.assertEqual(1, len(l7policies))
        self.assertEqual(l7policy2[const.DESCRIPTION],
                         l7policies[0][const.DESCRIPTION])

        # Test combined params
        l7policies = self.mem_l7policy_client.list_l7policies(
            query_params='listener_id={listener_id}&{admin}={true}&'
                         '{fields}={descr}&{fields}={id}&'
                         '{sort}={descr}:{desc}'.format(
                             listener_id=listener_id,
                             admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, descr=const.DESCRIPTION,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        # Should get two l7policies
        self.assertEqual(2, len(l7policies))
        # l7policies should have two fields
        self.assertEqual(2, len(l7policies[0]))
        # Should be in descending order
        self.assertEqual(l7policy2[const.DESCRIPTION],
                         l7policies[1][const.DESCRIPTION])
        self.assertEqual(l7policy1[const.DESCRIPTION],
                         l7policies[0][const.DESCRIPTION])

        # Creating a list of 3 l7policies, each one contains different tags
        if self.mem_l7policy_client.is_version_supported(
                self.api_version, '2.5'):
            list_of_l7policies = [l7policy1, l7policy2, l7policy3]
            test_list = []
            for l7policy in list_of_l7policies:

                # If tags "English" and "Creativity" are in the l7policy's tags
                # and "Spanish" is not, add the l7policy to the list
                if "English" in l7policy[const.TAGS] and "Creativity" in (
                        l7policy[const.TAGS]) and "Spanish" not in (
                        l7policy[const.TAGS]):
                    test_list.append(l7policy[const.NAME])

            # Tests if only the first and the third ones have those tags
            self.assertEqual(
                test_list, [l7policy1[const.NAME], l7policy3[const.NAME]])

            # Tests that filtering by an empty tag will return an empty list
            self.assertTrue(not any(["" in l7policy[const.TAGS]
                                     for l7policy in list_of_l7policies]))

    @decorators.idempotent_id('baaa8104-a037-4976-b908-82a0b3e08129')
    def test_l7policy_show(self):
        """Tests l7policy show API.

        * Create a fully populated l7policy.
        * Show l7policy details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the l7policy.
        """
        listener_name = data_utils.rand_name(
            "lb_member_listener4_l7policy-show")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '81',
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
        l7policy_name = data_utils.rand_name("lb_member_l7policy1-show")
        l7policy_description = data_utils.arbitrary_string(size=255)
        l7policy_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy_name,
            const.DESCRIPTION: l7policy_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 1,
            const.ACTION: const.REJECT,
        }

        l7policy = self.mem_l7policy_client.create_l7policy(**l7policy_kwargs)

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
        if not CONF.load_balancer.test_with_noop:
            l7policy = waiters.wait_for_status(
                self.mem_l7policy_client.show_l7policy,
                l7policy[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(l7policy_name, l7policy[const.NAME])
        self.assertEqual(l7policy_description, l7policy[const.DESCRIPTION])
        self.assertTrue(l7policy[const.ADMIN_STATE_UP])
        parser.parse(l7policy[const.CREATED_AT])
        parser.parse(l7policy[const.UPDATED_AT])
        UUID(l7policy[const.ID])
        # Operating status for a l7policy will be ONLINE if it is enabled:
        if l7policy[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7policy[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7policy[const.OPERATING_STATUS])
        self.assertEqual(listener_id, l7policy[const.LISTENER_ID])
        self.assertEqual(1, l7policy[const.POSITION])
        self.assertEqual(const.REJECT, l7policy[const.ACTION])
        self.assertIsNone(l7policy.pop(const.REDIRECT_URL, None))
        self.assertIsNone(l7policy.pop(const.REDIRECT_POOL_ID, None))

        # Test that the appropriate users can see or not see the L7 policies
        # based on the API RBAC.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'L7PolicyClient', 'show_l7policy',
                expected_allowed, l7policy[const.ID])

    @decorators.idempotent_id('08f73b22-550b-4e5a-b3d6-2ec03251ca13')
    def test_l7policy_update(self):
        """Tests l7policy update and show APIs.

        * Create a clean listener.
        * Create a fully populated l7policy.
        * Show l7policy details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the l7policy.
        * Update the l7policy details.
        * Show l7policy details.
        * Validate the show reflects the updated values.
        """
        listener_name = data_utils.rand_name(
            "lb_member_listener3_l7policy-update")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '81',
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

        l7policy_name = data_utils.rand_name("lb_member_l7policy1-update")
        l7policy_description = data_utils.arbitrary_string(size=255)
        l7_redirect_url = 'http://localhost'
        l7policy_kwargs = {
            const.LISTENER_ID: listener_id,
            const.NAME: l7policy_name,
            const.DESCRIPTION: l7policy_description,
            const.ADMIN_STATE_UP: False,
            const.POSITION: 1,
            const.ACTION: const.REDIRECT_TO_URL,
            const.REDIRECT_URL: l7_redirect_url,
        }

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            l7_policy_tags = ["Hello", "World"]
            l7policy_kwargs.update({
                const.TAGS: l7_policy_tags
            })

        l7policy = self.mem_l7policy_client.create_l7policy(**l7policy_kwargs)

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
        # Operating status for a l7policy will be ONLINE if it is enabled:
        if l7policy[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7policy[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7policy[const.OPERATING_STATUS])
        self.assertEqual(listener_id, l7policy[const.LISTENER_ID])
        self.assertEqual(1, l7policy[const.POSITION])
        self.assertEqual(const.REDIRECT_TO_URL, l7policy[const.ACTION])
        self.assertEqual(l7_redirect_url, l7policy[const.REDIRECT_URL])
        self.assertIsNone(l7policy.pop(const.REDIRECT_POOL_ID, None))

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(l7policy_kwargs[const.TAGS],
                                  l7policy[const.TAGS])

        # Test that a user, without the loadbalancer member role, cannot
        # update this L7 policy.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'L7PolicyClient', 'update_l7policy',
                expected_allowed, None, None, l7policy[const.ID],
                admin_state_up=True)

        # Assert we didn't go into PENDING_*
        l7policy_check = self.mem_l7policy_client.show_l7policy(
            l7policy[const.ID])
        self.assertEqual(const.ACTIVE,
                         l7policy_check[const.PROVISIONING_STATUS])
        self.assertFalse(l7policy_check[const.ADMIN_STATE_UP])

        new_name = data_utils.rand_name("lb_member_l7policy1-UPDATED")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        l7policy_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.POSITION: 2,
            const.ACTION: const.REDIRECT_TO_POOL,
            const.REDIRECT_POOL_ID: self.pool_id,
        }

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            l7_policy_new_tags = ["Hola", "Mundo"]
            l7policy_update_kwargs.update({
                const.TAGS: l7_policy_new_tags
            })

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
        if not CONF.load_balancer.test_with_noop:
            l7policy = waiters.wait_for_status(
                self.mem_l7policy_client.show_l7policy,
                l7policy[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(new_name, l7policy[const.NAME])
        self.assertEqual(new_description, l7policy[const.DESCRIPTION])
        self.assertTrue(l7policy[const.ADMIN_STATE_UP])
        parser.parse(l7policy[const.CREATED_AT])
        parser.parse(l7policy[const.UPDATED_AT])
        UUID(l7policy[const.ID])
        # Operating status for a l7policy will be ONLINE if it is enabled:
        if l7policy[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, l7policy[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, l7policy[const.OPERATING_STATUS])
        self.assertEqual(listener_id, l7policy[const.LISTENER_ID])
        self.assertEqual(1, l7policy[const.POSITION])
        self.assertEqual(const.REDIRECT_TO_POOL, l7policy[const.ACTION])
        self.assertEqual(self.pool_id, l7policy[const.REDIRECT_POOL_ID])
        self.assertIsNone(l7policy.pop(const.REDIRECT_URL, None))

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(l7policy_update_kwargs[const.TAGS],
                                  l7policy[const.TAGS])

    @decorators.idempotent_id('7925eb4b-94b6-4c28-98c2-fd0b4f0976cc')
    def test_l7policy_delete(self):
        """Tests l7policy create and delete APIs.

        * Creates a l7policy.
        * Validates that other accounts cannot delete the l7policy
        * Deletes the l7policy.
        * Validates the l7policy is in the DELETED state.
        """
        l7policy_name = data_utils.rand_name("lb_member_l7policy1-delete")
        l7policy_kwargs = {
            const.LISTENER_ID: self.listener_id,
            const.NAME: l7policy_name,
            const.ACTION: const.REJECT,
        }
        l7policy = self.mem_l7policy_client.create_l7policy(**l7policy_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the loadbalancer role cannot delete this
        # L7 policy.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_delete_RBAC_enforcement(
                'L7PolicyClient', 'delete_l7policy',
                expected_allowed, None, None, l7policy[const.ID])

        self.mem_l7policy_client.delete_l7policy(l7policy[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_l7policy_client.show_l7policy, l7policy[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
