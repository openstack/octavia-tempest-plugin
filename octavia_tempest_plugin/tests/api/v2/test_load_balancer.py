# Copyright 2017 GoDaddy
# Copyright 2017 Catalyst IT Ltd
# Copyright 2018 Rackspace US Inc.  All rights reserved.
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

import copy
import testtools
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


class LoadBalancerAPITest(test_base.LoadBalancerBaseTest):
    """Test the load balancer object API."""

    # Note: This test also covers basic load balancer show API
    @decorators.idempotent_id('61c6343c-a5d2-4b9f-8c7d-34ea83f0596b')
    def test_load_balancer_ipv4_create(self):
        self._test_load_balancer_create(4)

    # Note: This test also covers basic load balancer show API
    @decorators.idempotent_id('fc9996de-4f55-4fc4-b8ef-a4b9170c7078')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_load_balancer_ipv6_create(self):
        self._test_load_balancer_create(6)

    def _test_load_balancer_create(self, ip_version):
        """Tests load balancer create and basic show APIs.

        * Tests that users without the load balancer member role cannot
          create load balancers.
        * Create a fully populated load balancer.
        * Show load balancer details.
        * Validate the show reflects the requested values.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-create-"
                                       "ipv{}".format(ip_version))
        lb_description = data_utils.arbitrary_string(size=255)

        lb_kwargs = {const.ADMIN_STATE_UP: True,
                     const.DESCRIPTION: lb_description,
                     const.PROVIDER: CONF.load_balancer.provider,
                     # TODO(johnsom) Fix test to use a real flavor
                     # flavor=lb_flavor,
                     # TODO(johnsom) Add QoS
                     # vip_qos_policy_id=lb_qos_policy_id)
                     const.NAME: lb_name}

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            lb_tags = ["Hello", "World"]
            lb_kwargs.update({
                const.TAGS: lb_tags
            })

        self._setup_lb_network_kwargs(lb_kwargs, ip_version, use_fixed_ip=True)

        # Test that a user without the loadbalancer role cannot
        # create a load balancer.
        lb_kwargs_with_project_id = copy.deepcopy(lb_kwargs)
        lb_kwargs_with_project_id[const.PROJECT_ID] = (
            self.os_roles_lb_member.credentials.project_id)
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_primary', 'os_roles_lb_admin',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'LoadbalancerClient', 'create_loadbalancer',
                expected_allowed, None, None, **lb_kwargs_with_project_id)

        lb = self.mem_lb_client.create_loadbalancer(**lb_kwargs)

        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)
        if not CONF.load_balancer.test_with_noop:
            lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                         lb[const.ID], const.OPERATING_STATUS,
                                         const.ONLINE,
                                         CONF.load_balancer.check_interval,
                                         CONF.load_balancer.check_timeout)

        self.assertTrue(lb[const.ADMIN_STATE_UP])
        parser.parse(lb[const.CREATED_AT])
        parser.parse(lb[const.UPDATED_AT])
        self.assertEqual(lb_description, lb[const.DESCRIPTION])
        UUID(lb[const.ID])
        self.assertEqual(lb_name, lb[const.NAME])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, lb[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, lb[const.OPERATING_STATUS])
            if ip_version == 4:
                self.assertEqual(self.lb_member_vip_net[const.ID],
                                 lb[const.VIP_NETWORK_ID])
            else:
                self.assertEqual(self.lb_member_vip_ipv6_net[const.ID],
                                 lb[const.VIP_NETWORK_ID])

        self.assertEqual(self.os_roles_lb_member.credentials.project_id,
                         lb[const.PROJECT_ID])
        self.assertEqual(CONF.load_balancer.provider, lb[const.PROVIDER])
        self.assertIsNotNone(lb[const.VIP_PORT_ID])
        if lb_kwargs[const.VIP_SUBNET_ID]:
            if ip_version == 4 or self.lb_member_vip_ipv6_subnet_stateful:
                self.assertEqual(lb_kwargs[const.VIP_ADDRESS],
                                 lb[const.VIP_ADDRESS])
            self.assertEqual(lb_kwargs[const.VIP_SUBNET_ID],
                             lb[const.VIP_SUBNET_ID])

        # Attempt to clean up so that one full test run doesn't start 10+
        # amps before the cleanup phase fires
        try:
            self.mem_lb_client.delete_loadbalancer(lb[const.ID])

            waiters.wait_for_deleted_status_or_not_found(
                self.mem_lb_client.show_loadbalancer, lb[const.ID],
                const.PROVISIONING_STATUS,
                CONF.load_balancer.lb_build_interval,
                CONF.load_balancer.lb_build_timeout)
        except Exception:
            pass

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(lb_kwargs[const.TAGS], lb[const.TAGS])

    @decorators.idempotent_id('643ef031-c800-45f2-b229-3c8f8b37c829')
    def test_load_balancer_delete(self):
        """Tests load balancer create and delete APIs.

        * Creates a load balancer.
        * Validates that other accounts cannot delete the load balancer
        * Deletes the load balancer.
        * Validates the load balancer is in the DELETED state.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-delete")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
            vip_network_id=self.lb_member_vip_net[const.ID])
        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        # Test that a user without the loadbalancer role cannot delete this
        # load balancer.
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
                'LoadbalancerClient', 'delete_loadbalancer',
                expected_allowed, None, None, lb[const.ID])

        self.mem_lb_client.delete_loadbalancer(lb[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_lb_client.show_loadbalancer, lb[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)

    @decorators.idempotent_id('abd784e3-485f-442a-85da-d91365c6b5dd')
    def test_load_balancer_delete_cascade(self):
        """Tests load balancer create and cascade delete APIs.

        * Creates a load balancer.
        * Validates that other accounts cannot delete the load balancer
        * Deletes the load balancer with the cascade parameter.
        * Validates the load balancer is in the DELETED state.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-cascade_delete")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
            vip_network_id=self.lb_member_vip_net[const.ID])
        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        # TODO(johnsom) Add other objects when we have clients for them

        # Test that a user without the loadbalancer role cannot delete this
        # load balancer.
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
                'LoadbalancerClient', 'delete_loadbalancer',
                expected_allowed, None, None, lb[const.ID], cascade=True)

        self.mem_lb_client.delete_loadbalancer(lb[const.ID], cascade=True)

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_lb_client.show_loadbalancer, lb[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)

    # Helper functions for test loadbalancer list
    def _filter_lbs_by_id(self, lbs, ids):
        return [lb for lb in lbs if lb['id'] not in ids]

    def _filter_lbs_by_index(self, lbs, indexes):
        return [lb for i, lb in enumerate(lbs) if i not in indexes]

    @decorators.idempotent_id('6546ef3c-c0e2-46af-b892-f795f4d01119')
    def test_load_balancer_list(self):
        """Tests load balancer list API and field filtering.

        * Create three load balancers.
        * Validates that other accounts cannot list the load balancers.
        * List the load balancers using the default sort order.
        * List the load balancers using descending sort order.
        * List the load balancers using ascending sort order.
        * List the load balancers returning one field at a time.
        * List the load balancers returning two fields.
        * List the load balancers filtering to one of the three.
        * List the load balancers filtered, one field, and sorted.
        """
        # IDs of load balancers created in the test
        test_ids = []
        # Get a list of pre-existing LBs to filter from test data
        pretest_lbs = self.mem_lb_client.list_loadbalancers()
        # Store their IDs for easy access
        pretest_lb_ids = [lb['id'] for lb in pretest_lbs]

        lb_name = data_utils.rand_name("lb_member_lb2-list")
        lb_description = data_utils.rand_name('B')
        lb_admin_state_up = True
        lb_provider = CONF.load_balancer.provider
        lb_vip_network_id = self.lb_member_vip_net[const.ID]

        lb_kwargs = {
            const.ADMIN_STATE_UP: lb_admin_state_up,
            const.DESCRIPTION: lb_description,
            # TODO(johnsom) Fix test to use a real flavor
            # flavor=lb_flavor,
            const.PROVIDER: lb_provider,
            const.NAME: lb_name,
            # TODO(johnsom) Add QoS
            # vip_qos_policy_id=lb_qos_policy_id)
            const.VIP_NETWORK_ID: lb_vip_network_id
        }

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            lb_tags = ["English", "Mathematics", "Marketing", "Creativity"]
            lb_kwargs.update({const.TAGS: lb_tags})

        lb = self.mem_lb_client.create_loadbalancer(
            **lb_kwargs)

        self.addCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb1 = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                      lb[const.ID],
                                      const.PROVISIONING_STATUS,
                                      const.ACTIVE,
                                      CONF.load_balancer.lb_build_interval,
                                      CONF.load_balancer.lb_build_timeout)
        if not CONF.load_balancer.test_with_noop:
            lb1 = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                          lb[const.ID], const.OPERATING_STATUS,
                                          const.ONLINE,
                                          CONF.load_balancer.check_interval,
                                          CONF.load_balancer.check_timeout)
        test_ids.append(lb1[const.ID])

        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        lb_name = data_utils.rand_name("lb_member_lb1-list")
        lb_description = data_utils.rand_name('A')
        lb_admin_state_up = True
        lb_provider = CONF.load_balancer.provider
        lb_vip_network_id = self.lb_member_vip_net[const.ID]

        lb_kwargs = {
            const.ADMIN_STATE_UP: lb_admin_state_up,
            const.DESCRIPTION: lb_description,
            const.PROVIDER: lb_provider,
            const.NAME: lb_name,
            const.VIP_NETWORK_ID: lb_vip_network_id,
        }

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            lb_tags = ["English", "Spanish", "Soft_skills", "Creativity"]
            lb_kwargs.update({const.TAGS: lb_tags})

        lb = self.mem_lb_client.create_loadbalancer(
            **lb_kwargs)

        self.addCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb2 = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                      lb[const.ID],
                                      const.PROVISIONING_STATUS,
                                      const.ACTIVE,
                                      CONF.load_balancer.lb_build_interval,
                                      CONF.load_balancer.lb_build_timeout)
        if not CONF.load_balancer.test_with_noop:
            lb2 = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                          lb[const.ID], const.OPERATING_STATUS,
                                          const.ONLINE,
                                          CONF.load_balancer.check_interval,
                                          CONF.load_balancer.check_timeout)
        test_ids.append(lb2[const.ID])

        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        lb_name = data_utils.rand_name("lb_member_lb3-list")
        lb_description = data_utils.rand_name('C')
        lb_admin_state_up = False
        lb_provider = CONF.load_balancer.provider
        lb_vip_network_id = self.lb_member_vip_net[const.ID]

        lb_kwargs = {
            const.ADMIN_STATE_UP: lb_admin_state_up,
            const.DESCRIPTION: lb_description,
            const.PROVIDER: lb_provider,
            const.NAME: lb_name,
            const.VIP_NETWORK_ID: lb_vip_network_id,
        }

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            lb_tags = ["English", "Project_management",
                       "Communication", "Creativity"]
            lb_kwargs.update({const.TAGS: lb_tags})

        lb = self.mem_lb_client.create_loadbalancer(
            **lb_kwargs)

        self.addCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb3 = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                      lb[const.ID],
                                      const.PROVISIONING_STATUS,
                                      const.ACTIVE,
                                      CONF.load_balancer.lb_build_interval,
                                      CONF.load_balancer.lb_build_timeout)
        test_ids.append(lb3[const.ID])

        # Test that a different users cannot see the lb_member load balancers.
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
                'LoadbalancerClient', 'list_loadbalancers',
                expected_allowed, 0)

        # Test credentials that should see these load balancers can see them.
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
                'LoadbalancerClient', 'list_loadbalancers',
                expected_allowed, test_ids)

        # Test that users without the lb member role cannot list load balancers
        # Note: non-owners can still call this API, they will just get the list
        #       of load balancers for their project (zero). The above tests
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
                'LoadbalancerClient', 'list_loadbalancers', expected_allowed)

        # Check the default sort order, created_at
        lbs = self.mem_lb_client.list_loadbalancers()
        lbs = self._filter_lbs_by_id(lbs, pretest_lb_ids)
        self.assertEqual(lb1[const.DESCRIPTION], lbs[0][const.DESCRIPTION])
        self.assertEqual(lb2[const.DESCRIPTION], lbs[1][const.DESCRIPTION])
        self.assertEqual(lb3[const.DESCRIPTION], lbs[2][const.DESCRIPTION])

        # Test sort descending by description
        lbs = self.mem_lb_client.list_loadbalancers(
            query_params='{sort}={descr}:{desc}'.format(
                sort=const.SORT, descr=const.DESCRIPTION, desc=const.DESC))
        lbs = self._filter_lbs_by_id(lbs, pretest_lb_ids)
        self.assertEqual(lb1[const.DESCRIPTION], lbs[1][const.DESCRIPTION])
        self.assertEqual(lb2[const.DESCRIPTION], lbs[2][const.DESCRIPTION])
        self.assertEqual(lb3[const.DESCRIPTION], lbs[0][const.DESCRIPTION])

        # Test sort ascending by description
        lbs = self.mem_lb_client.list_loadbalancers(
            query_params='{sort}={descr}:{asc}'.format(sort=const.SORT,
                                                       descr=const.DESCRIPTION,
                                                       asc=const.ASC))
        lbs = self._filter_lbs_by_id(lbs, pretest_lb_ids)
        self.assertEqual(lb1[const.DESCRIPTION], lbs[1][const.DESCRIPTION])
        self.assertEqual(lb2[const.DESCRIPTION], lbs[0][const.DESCRIPTION])
        self.assertEqual(lb3[const.DESCRIPTION], lbs[2][const.DESCRIPTION])

        # Determine indexes of pretest LBs in default sort
        pretest_lb_indexes = []
        lbs = self.mem_lb_client.list_loadbalancers()
        for i, lb in enumerate(lbs):
            if lb['id'] in pretest_lb_ids:
                pretest_lb_indexes.append(i)

        # Test fields
        for field in const.SHOW_LOAD_BALANCER_RESPONSE_FIELDS:
            lbs = self.mem_lb_client.list_loadbalancers(
                query_params='{fields}={field}'.format(fields=const.FIELDS,
                                                       field=field))
            lbs = self._filter_lbs_by_index(lbs, pretest_lb_indexes)
            self.assertEqual(1, len(lbs[0]))
            self.assertEqual(lb1[field], lbs[0][field])
            self.assertEqual(lb2[field], lbs[1][field])
            self.assertEqual(lb3[field], lbs[2][field])

        # Test multiple fields at the same time
        lbs = self.mem_lb_client.list_loadbalancers(
            query_params='{fields}={admin}&{fields}={created}'.format(
                fields=const.FIELDS, admin=const.ADMIN_STATE_UP,
                created=const.CREATED_AT))
        lbs = self._filter_lbs_by_index(lbs, pretest_lb_indexes)
        self.assertEqual(2, len(lbs[0]))
        self.assertTrue(lbs[0][const.ADMIN_STATE_UP])
        parser.parse(lbs[0][const.CREATED_AT])
        self.assertTrue(lbs[1][const.ADMIN_STATE_UP])
        parser.parse(lbs[1][const.CREATED_AT])
        self.assertFalse(lbs[2][const.ADMIN_STATE_UP])
        parser.parse(lbs[2][const.CREATED_AT])

        # Test filtering
        lbs = self.mem_lb_client.list_loadbalancers(
            query_params='{desc}={lb_desc}'.format(
                desc=const.DESCRIPTION, lb_desc=lb2[const.DESCRIPTION]))
        self.assertEqual(1, len(lbs))
        self.assertEqual(lb2[const.DESCRIPTION], lbs[0][const.DESCRIPTION])

        # Test combined params
        lbs = self.mem_lb_client.list_loadbalancers(
            query_params='{admin}={true}&{fields}={descr}&{fields}={id}&'
                         '{sort}={descr}:{desc}'.format(
                             admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, descr=const.DESCRIPTION,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        lbs = self._filter_lbs_by_id(lbs, pretest_lb_ids)
        # Should get two load balancers
        self.assertEqual(2, len(lbs))
        # Load balancers should have two fields
        self.assertEqual(2, len(lbs[0]))
        # Should be in descending order
        self.assertEqual(lb2[const.DESCRIPTION], lbs[1][const.DESCRIPTION])
        self.assertEqual(lb1[const.DESCRIPTION], lbs[0][const.DESCRIPTION])

        # Creating a list of 3 LBs, each one contains different tags
        if self.mem_lb_client.is_version_supported(
                self.api_version, '2.5'):
            list_of_lbs = [lb1, lb2, lb3]
            test_list = []
            for lb in list_of_lbs:

                # If tags "English" and "Creativity" are in the LB's tags
                # and "Spanish" is not, add the LB to the list
                if "English" in lb[const.TAGS] and "Creativity" in (
                    lb[const.TAGS]) and "Spanish" not in (
                        lb[const.TAGS]):
                    test_list.append(lb[const.NAME])

            # Tests if only the first and the third ones have those tags
            self.assertEqual(
                test_list, [lb1[const.NAME], lb3[const.NAME]])

            # Tests that filtering by an empty tag will return an empty list
            self.assertTrue(not any(["" in lb[const.TAGS]
                                     for lb in list_of_lbs]))

    @decorators.idempotent_id('826ae612-8717-4c64-a8a7-cb9570a85870')
    def test_load_balancer_show(self):
        """Tests load balancer show API.

        * Create a fully populated load balancer.
        * Show load balancer details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the load balancer.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-show")
        lb_description = data_utils.arbitrary_string(size=255)

        lb_kwargs = {const.ADMIN_STATE_UP: False,
                     const.DESCRIPTION: lb_description,
                     # TODO(johnsom) Fix test to use a real flavor
                     # flavor=lb_flavor,
                     # TODO(johnsom) Add QoS
                     # vip_qos_policy_id=lb_qos_policy_id)
                     const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        self._setup_lb_network_kwargs(lb_kwargs, 4, use_fixed_ip=True)

        lb = self.mem_lb_client.create_loadbalancer(**lb_kwargs)

        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        self.assertFalse(lb[const.ADMIN_STATE_UP])
        parser.parse(lb[const.CREATED_AT])
        parser.parse(lb[const.UPDATED_AT])
        self.assertEqual(lb_description, lb[const.DESCRIPTION])
        UUID(lb[const.ID])
        self.assertEqual(lb_name, lb[const.NAME])
        self.assertEqual(const.OFFLINE, lb[const.OPERATING_STATUS])
        self.assertEqual(self.os_roles_lb_member.credentials.project_id,
                         lb[const.PROJECT_ID])
        self.assertEqual(CONF.load_balancer.provider, lb[const.PROVIDER])
        self.assertEqual(self.lb_member_vip_net[const.ID],
                         lb[const.VIP_NETWORK_ID])
        self.assertIsNotNone(lb[const.VIP_PORT_ID])
        if lb_kwargs[const.VIP_SUBNET_ID]:
            self.assertEqual(lb_kwargs[const.VIP_ADDRESS],
                             lb[const.VIP_ADDRESS])
            self.assertEqual(lb_kwargs[const.VIP_SUBNET_ID],
                             lb[const.VIP_SUBNET_ID])

        # Test that the appropriate users can see or not see the load
        # balancer based on the API RBAC.
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
                'LoadbalancerClient', 'show_loadbalancer',
                expected_allowed, lb[const.ID])

        # Attempt to clean up so that one full test run doesn't start 10+
        # amps before the cleanup phase fires
        try:
            self.mem_lb_client.delete_loadbalancer(lb[const.ID])

            waiters.wait_for_deleted_status_or_not_found(
                self.mem_lb_client.show_loadbalancer, lb[const.ID],
                const.PROVISIONING_STATUS,
                CONF.load_balancer.lb_build_interval,
                CONF.load_balancer.lb_build_timeout)
        except Exception:
            pass

    @decorators.idempotent_id('b75a4d15-49d2-4149-a745-635eed1aacc3')
    def test_load_balancer_update(self):
        """Tests load balancer update and show APIs.

        * Create a fully populated load balancer.
        * Show load balancer details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the load balancer.
        * Update the load balancer details.
        * Show load balancer details.
        * Validate the show reflects the updated values.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-update")
        lb_description = data_utils.arbitrary_string(size=255)

        lb_kwargs = {const.ADMIN_STATE_UP: False,
                     const.DESCRIPTION: lb_description,
                     const.PROVIDER: CONF.load_balancer.provider,
                     # TODO(johnsom) Fix test to use a real flavor
                     # flavor=lb_flavor,
                     # TODO(johnsom) Add QoS
                     # vip_qos_policy_id=lb_qos_policy_id)
                     const.NAME: lb_name}

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            lb_tags = ["Hello", "World"]
            lb_kwargs.update({
                const.TAGS: lb_tags
            })

        self._setup_lb_network_kwargs(lb_kwargs, 4, use_fixed_ip=True)

        lb = self.mem_lb_client.create_loadbalancer(**lb_kwargs)

        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        self.assertFalse(lb[const.ADMIN_STATE_UP])
        parser.parse(lb[const.CREATED_AT])
        parser.parse(lb[const.UPDATED_AT])
        self.assertEqual(lb_description, lb[const.DESCRIPTION])
        UUID(lb[const.ID])
        self.assertEqual(lb_name, lb[const.NAME])
        self.assertEqual(const.OFFLINE, lb[const.OPERATING_STATUS])
        self.assertEqual(self.os_roles_lb_member.credentials.project_id,
                         lb[const.PROJECT_ID])
        self.assertEqual(CONF.load_balancer.provider, lb[const.PROVIDER])
        self.assertEqual(self.lb_member_vip_net[const.ID],
                         lb[const.VIP_NETWORK_ID])
        self.assertIsNotNone(lb[const.VIP_PORT_ID])
        if lb_kwargs[const.VIP_SUBNET_ID]:
            self.assertEqual(lb_kwargs[const.VIP_ADDRESS],
                             lb[const.VIP_ADDRESS])
            self.assertEqual(lb_kwargs[const.VIP_SUBNET_ID],
                             lb[const.VIP_SUBNET_ID])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(lb_kwargs[const.TAGS], lb[const.TAGS])

        new_name = data_utils.rand_name("lb_member_lb1-update")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')

        # Test that a user, without the loadbalancer member role, cannot
        # update this load balancer.
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
                'LoadbalancerClient', 'update_loadbalancer',
                expected_allowed, None, None, lb[const.ID],
                admin_state_up=True)

        # Assert we didn't go into PENDING_*
        lb_check = self.mem_lb_client.show_loadbalancer(lb[const.ID])
        self.assertEqual(const.ACTIVE, lb_check[const.PROVISIONING_STATUS])
        self.assertFalse(lb_check[const.ADMIN_STATE_UP])

        admin_state_up = True

        lb_update_kwargs = {
            # const.ID: lb[const.ID],
            const.ADMIN_STATE_UP: admin_state_up,
            const.DESCRIPTION: new_description,
            # TODO(johnsom) Add QoS
            # vip_qos_policy_id=lb_qos_policy_id)
            const.NAME: new_name
        }

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            new_tags = ["Hola", "Mundo"]
            lb_update_kwargs.update({
                const.TAGS: new_tags
            })

        lb = self.mem_lb_client.update_loadbalancer(
            lb[const.ID], **lb_update_kwargs)

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        self.assertTrue(lb[const.ADMIN_STATE_UP])
        self.assertEqual(new_description, lb[const.DESCRIPTION])
        self.assertEqual(new_name, lb[const.NAME])
        self.assertCountEqual(lb_update_kwargs[const.TAGS], lb[const.TAGS])
        # TODO(johnsom) Add QoS

        # Attempt to clean up so that one full test run doesn't start 10+
        # amps before the cleanup phase fires
        try:
            self.mem_lb_client.delete_loadbalancer(lb[const.ID])

            waiters.wait_for_deleted_status_or_not_found(
                self.mem_lb_client.show_loadbalancer, lb[const.ID],
                const.PROVISIONING_STATUS,
                CONF.load_balancer.lb_build_interval,
                CONF.load_balancer.lb_build_timeout)
        except Exception:
            pass

    @decorators.idempotent_id('105afcba-4dd6-46d6-8fa4-bd7330aa1259')
    def test_load_balancer_show_stats(self):
        """Tests load balancer show statistics API.

        * Create a load balancer.
        * Validates that other accounts cannot see the stats for the
        *   load balancer.
        * Show load balancer statistics.
        * Validate the show reflects the expected values.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-show_stats")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
            vip_network_id=self.lb_member_vip_net[const.ID])
        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        # Test that the appropriate users can see or not see the load
        # balancer stats based on the API RBAC.
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
                'LoadbalancerClient', 'get_loadbalancer_stats',
                expected_allowed, lb[const.ID])

        stats = self.mem_lb_client.get_loadbalancer_stats(lb[const.ID])

        self.assertEqual(5, len(stats))
        self.assertEqual(0, stats[const.ACTIVE_CONNECTIONS])
        self.assertEqual(0, stats[const.BYTES_IN])
        self.assertEqual(0, stats[const.BYTES_OUT])
        self.assertEqual(0, stats[const.REQUEST_ERRORS])
        self.assertEqual(0, stats[const.TOTAL_CONNECTIONS])

        # Attempt to clean up so that one full test run doesn't start 10+
        # amps before the cleanup phase fires
        try:
            self.mem_lb_client.delete_loadbalancer(lb[const.ID])

            waiters.wait_for_deleted_status_or_not_found(
                self.mem_lb_client.show_loadbalancer, lb[const.ID],
                const.PROVISIONING_STATUS,
                CONF.load_balancer.lb_build_interval,
                CONF.load_balancer.lb_build_timeout)
        except Exception:
            pass

    @decorators.idempotent_id('60acc1b0-fa46-41f8-b526-c81ae2f42c30')
    def test_load_balancer_show_status(self):
        """Tests load balancer show status tree API.

        * Create a load balancer.
        * Validates that other accounts cannot see the status for the
        *   load balancer.
        * Show load balancer status tree.
        * Validate the show reflects the expected values.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-status")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
            vip_network_id=self.lb_member_vip_net[const.ID])
        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)
        if not CONF.load_balancer.test_with_noop:
            lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                         lb[const.ID], const.OPERATING_STATUS,
                                         const.ONLINE,
                                         CONF.load_balancer.check_interval,
                                         CONF.load_balancer.check_timeout)

        # Test that the appropriate users can see or not see the load
        # balancer status based on the API RBAC.
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
                'LoadbalancerClient', 'get_loadbalancer_status',
                expected_allowed, lb[const.ID])

        status = self.mem_lb_client.get_loadbalancer_status(lb[const.ID])

        self.assertEqual(1, len(status))
        lb_status = status[const.LOADBALANCER]
        self.assertEqual(5, len(lb_status))
        self.assertEqual(lb[const.ID], lb_status[const.ID])
        self.assertEqual([], lb_status[const.LISTENERS])
        self.assertEqual(lb_name, lb_status[const.NAME])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, lb_status[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, lb_status[const.OPERATING_STATUS])
        self.assertEqual(const.ACTIVE, lb_status[const.PROVISIONING_STATUS])

        # Attempt to clean up so that one full test run doesn't start 10+
        # amps before the cleanup phase fires
        try:
            self.mem_lb_client.delete_loadbalancer(lb[const.ID])

            waiters.wait_for_deleted_status_or_not_found(
                self.mem_lb_client.show_loadbalancer, lb[const.ID],
                const.PROVISIONING_STATUS,
                CONF.load_balancer.lb_build_interval,
                CONF.load_balancer.lb_build_timeout)
        except Exception:
            pass

    @decorators.idempotent_id('fc2e07a6-9776-4559-90c9-141170d4c397')
    def test_load_balancer_failover(self):
        """Tests load balancer failover API.

        * Create a load balancer.
        * Validates that other accounts cannot failover the load balancer
        * Wait for the load balancer to go ACTIVE.
        * Failover the load balancer.
        * Wait for the load balancer to go ACTIVE.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-failover")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
            vip_network_id=self.lb_member_vip_net[const.ID])
        self.addClassResourceCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        # Test RBAC not authorized for non-admin role
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            self.assertRaises(exceptions.Forbidden,
                              self.mem_lb_client.failover_loadbalancer,
                              lb[const.ID])

        # Test that a user without the load balancer admin role cannot
        # failover a load balancer.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'LoadbalancerClient', 'failover_loadbalancer',
                expected_allowed, None, None, lb[const.ID])

        # Assert we didn't go into PENDING_*
        lb = self.mem_lb_client.show_loadbalancer(lb[const.ID])
        self.assertEqual(const.ACTIVE, lb[const.PROVISIONING_STATUS])

        if CONF.load_balancer.provider in const.AMPHORA_PROVIDERS:
            before_amphorae = self.lb_admin_amphora_client.list_amphorae(
                query_params='{loadbalancer_id}={lb_id}'.format(
                    loadbalancer_id=const.LOADBALANCER_ID, lb_id=lb[const.ID]))

        admin_lb_client = (
            self.os_roles_lb_admin.load_balancer_v2.LoadbalancerClient())
        admin_lb_client.failover_loadbalancer(lb[const.ID])

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        if CONF.load_balancer.provider in const.AMPHORA_PROVIDERS:
            after_amphorae = self.lb_admin_amphora_client.list_amphorae(
                query_params='{loadbalancer_id}={lb_id}'.format(
                    loadbalancer_id=const.LOADBALANCER_ID, lb_id=lb[const.ID]))

            # Make sure all of the amphora on the load balancer have
            # failed over
            for amphora in before_amphorae:
                for new_amp in after_amphorae:
                    self.assertNotEqual(amphora[const.ID], new_amp[const.ID])

        # Attempt to clean up so that one full test run doesn't start 10+
        # amps before the cleanup phase fires
        try:
            self.mem_lb_client.delete_loadbalancer(lb[const.ID])

            waiters.wait_for_deleted_status_or_not_found(
                self.mem_lb_client.show_loadbalancer, lb[const.ID],
                const.PROVISIONING_STATUS,
                CONF.load_balancer.lb_build_interval,
                CONF.load_balancer.lb_build_timeout)
        except Exception:
            pass
