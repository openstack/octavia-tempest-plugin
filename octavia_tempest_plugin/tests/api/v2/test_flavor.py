#    Copyright 2019 Rackspace US Inc.  All rights reserved.
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
from operator import itemgetter
from uuid import UUID

from oslo_serialization import jsonutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base

CONF = config.CONF


class FlavorAPITest(test_base.LoadBalancerBaseTest):
    """Test the flavor object API."""

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(FlavorAPITest, cls).resource_setup()

        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not cls.lb_admin_flavor_profile_client.is_version_supported(
                cls.api_version, '2.6'):
            return

        # Create a shared flavor profile
        flavor_profile_name = data_utils.rand_name(
            "lb_admin_flavorprofile-setup")
        flavor_data = {const.LOADBALANCER_TOPOLOGY: const.SINGLE}
        flavor_data_json = jsonutils.dumps(flavor_data)

        flavor_profile_kwargs = {
            const.NAME: flavor_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data_json
        }

        cls.flavor_profile = (
            cls.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile_kwargs))
        cls.addClassResourceCleanup(
            cls.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            cls.flavor_profile[const.ID])
        cls.flavor_profile_id = cls.flavor_profile[const.ID]

    @decorators.idempotent_id('7e8f39ce-53e0-4364-8778-6da9b9a59e5a')
    def test_flavor_create(self):
        """Tests flavor create and basic show APIs.

        * Tests that users without the loadbalancer admin role cannot
          create a flavor.
        * Create a fully populated flavor.
        * Validate the response reflects the requested values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavors are only available on '
                                     'Octavia API version 2.6 or newer.')
        flavor_name = data_utils.rand_name("lb_admin_flavor-create")
        flavor_description = data_utils.arbitrary_string(size=255)

        flavor_kwargs = {
            const.NAME: flavor_name,
            const.DESCRIPTION: flavor_description,
            const.ENABLED: True,
            const.FLAVOR_PROFILE_ID: self.flavor_profile_id}

        # Test that a user without the load balancer admin role cannot
        # create a flavor.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'FlavorClient', 'create_flavor',
                expected_allowed, None, None, **flavor_kwargs)

        # Happy path
        flavor = self.lb_admin_flavor_client.create_flavor(**flavor_kwargs)
        self.addCleanup(self.lb_admin_flavor_client.cleanup_a_flavor,
                        flavor[const.ID])

        UUID(flavor[const.ID])
        self.assertEqual(flavor_name, flavor[const.NAME])
        self.assertEqual(flavor_description, flavor[const.DESCRIPTION])
        self.assertTrue(flavor[const.ENABLED])
        self.assertEqual(self.flavor_profile_id,
                         flavor[const.FLAVOR_PROFILE_ID])

        # Test that flavors do not support tags
        flavor_tags = ["Hello", "World"]
        tags_flavor_kwargs = flavor_kwargs.copy()
        tags_flavor_kwargs[const.TAGS] = flavor_tags
        self.assertRaises(TypeError,
                          self.lb_admin_flavor_client.create_flavor,
                          **tags_flavor_kwargs)

    @decorators.idempotent_id('3ef040ee-fe7e-457b-a56f-8b152f7afa3b')
    def test_flavor_list(self):
        """Tests flavor list API and field filtering.

        * Create three flavors.
        * Validates that non-admin accounts cannot list the flavors.
        * List the flavors using the default sort order.
        * List the flavors using descending sort order.
        * List the flavors using ascending sort order.
        * List the flavors returning one field at a time.
        * List the flavors returning two fields.
        * List the flavors filtering to one of the three.
        * List the flavors filtered, one field, and sorted.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavors are only available on '
                                     'Octavia API version 2.6 or newer.')

        # Create flavor 1
        flavor1_name = data_utils.rand_name("lb_admin_flavor-list-1")
        flavor1_description = 'A'

        flavor1_kwargs = {
            const.NAME: flavor1_name,
            const.DESCRIPTION: flavor1_description,
            const.ENABLED: True,
            const.FLAVOR_PROFILE_ID: self.flavor_profile_id}

        flavor1 = (self.lb_admin_flavor_client.create_flavor(**flavor1_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_client.cleanup_a_flavor, flavor1[const.ID])

        # Create flavor 2
        flavor2_name = data_utils.rand_name("lb_admin_flavor-list-2")
        flavor2_description = 'B'

        flavor2_kwargs = {
            const.NAME: flavor2_name,
            const.DESCRIPTION: flavor2_description,
            const.ENABLED: False,
            const.FLAVOR_PROFILE_ID: self.flavor_profile_id}

        flavor2 = (self.lb_admin_flavor_client.create_flavor(**flavor2_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_client.cleanup_a_flavor, flavor2[const.ID])

        # Create flavor 3
        flavor3_name = data_utils.rand_name("lb_admin_flavor-list-3")
        flavor3_description = 'C'

        flavor3_kwargs = {
            const.NAME: flavor3_name,
            const.DESCRIPTION: flavor3_description,
            const.ENABLED: True,
            const.FLAVOR_PROFILE_ID: self.flavor_profile_id}

        flavor3 = (self.lb_admin_flavor_client.create_flavor(**flavor3_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_client.cleanup_a_flavor, flavor3[const.ID])

        # default sort order (by ID) reference list
        ref_id_list_asc = [flavor1[const.ID], flavor2[const.ID],
                           flavor3[const.ID]]
        ref_id_list_dsc = copy.deepcopy(ref_id_list_asc)
        ref_id_list_asc.sort()
        ref_id_list_dsc.sort(reverse=True)

        # Test that a user without the load balancer role cannot
        # list flavors.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = [
                'os_admin', 'os_primary', 'os_roles_lb_admin',
                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_primary', 'os_system_admin',
                                'os_system_reader', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = [
                'os_system_admin', 'os_system_reader', 'os_roles_lb_admin',
                'os_roles_lb_observer', 'os_roles_lb_global_observer',
                'os_roles_lb_member', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'FlavorClient', 'list_flavors', expected_allowed)

        # Check the default sort order (by ID)
        flavors = self.mem_flavor_client.list_flavors()
        # Remove flavors not used in this test
        flavors = [flav for flav in flavors
                   if 'lb_admin_flavor-list' in flav[const.NAME]]
        self.assertEqual(3, len(flavors))
        self.assertEqual(ref_id_list_asc[0], flavors[0][const.ID])
        self.assertEqual(ref_id_list_asc[1], flavors[1][const.ID])
        self.assertEqual(ref_id_list_asc[2], flavors[2][const.ID])

        # Check the descending sort order by name
        flavors = self.lb_admin_flavor_client.list_flavors(
            query_params='{sort}={name}:{order}'.format(
                sort=const.SORT, name=const.NAME, order=const.DESC))
        # Remove flavors not used in this test
        flavors = [flav for flav in flavors
                   if 'lb_admin_flavor-list' in flav[const.NAME]]
        self.assertEqual(3, len(flavors))
        self.assertEqual(flavor3_name, flavors[0][const.NAME])
        self.assertEqual(flavor2_name, flavors[1][const.NAME])
        self.assertEqual(flavor1_name, flavors[2][const.NAME])

        # Check the ascending sort order by name
        flavors = self.mem_flavor_client.list_flavors(
            query_params='{sort}={name}:{order}'.format(
                sort=const.SORT, name=const.NAME, order=const.ASC))
        # Remove flavors not used in this test
        flavors = [flav for flav in flavors
                   if 'lb_admin_flavor-list' in flav[const.NAME]]
        self.assertEqual(3, len(flavors))
        self.assertEqual(flavor1_name, flavors[0][const.NAME])
        self.assertEqual(flavor2_name, flavors[1][const.NAME])
        self.assertEqual(flavor3_name, flavors[2][const.NAME])

        ref_flavors = [flavor1, flavor2, flavor3]
        sorted_flavors = sorted(ref_flavors, key=itemgetter(const.ID))
        sorted_enabled_flavors = [flav for flav in sorted_flavors
                                  if flav[const.ENABLED]]

        # Test fields
        for field in const.SHOW_FLAVOR_FIELDS:
            flavors = self.mem_flavor_client.list_flavors(
                query_params='{fields}={field}&{fields}={name}'.format(
                    fields=const.FIELDS, field=field, name=const.NAME))
            # Remove flavors not used in this test
            flavors = [flav for flav in flavors
                       if 'lb_admin_flavor-list' in flav[const.NAME]]
            self.assertEqual(3, len(flavors))
            self.assertEqual(sorted_flavors[0][field], flavors[0][field])
            self.assertEqual(sorted_flavors[1][field], flavors[1][field])
            self.assertEqual(sorted_flavors[2][field], flavors[2][field])

        # Test filtering
        flavor = self.mem_flavor_client.list_flavors(
            query_params='{name}={flav_name}'.format(
                name=const.NAME, flav_name=flavor2[const.NAME]))
        self.assertEqual(1, len(flavor))
        self.assertEqual(flavor2[const.ID], flavor[0][const.ID])

        # Test combined params
        flavors = self.mem_flavor_client.list_flavors(
            query_params='{enabled}={enable}&{fields}={name}&'
                         '{sort}={ID}:{desc}'.format(
                             enabled=const.ENABLED,
                             enable=True,
                             fields=const.FIELDS, name=const.NAME,
                             sort=const.SORT, ID=const.ID,
                             desc=const.DESC))
        # Remove flavors not used in this test
        flavors = [flav for flav in flavors
                   if 'lb_admin_flavor-list' in flav[const.NAME]]
        self.assertEqual(2, len(flavors))
        self.assertEqual(1, len(flavors[0]))
        self.assertEqual(sorted_enabled_flavors[1][const.NAME],
                         flavors[0][const.NAME])
        self.assertEqual(sorted_enabled_flavors[0][const.NAME],
                         flavors[1][const.NAME])

    @decorators.idempotent_id('7492a862-4011-4924-8e81-70763f479cf8')
    def test_flavor_show(self):
        """Tests flavor show API.

        * Create a fully populated flavor.
        * Validates that non-lb-admin accounts cannot see the flavor.
        * Show flavor details.
        * Validate the show reflects the requested values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavors are only available on '
                                     'Octavia API version 2.6 or newer.')
        flavor_name = data_utils.rand_name("lb_admin_flavor-show")
        flavor_description = data_utils.arbitrary_string(size=255)

        flavor_kwargs = {
            const.NAME: flavor_name,
            const.DESCRIPTION: flavor_description,
            const.ENABLED: True,
            const.FLAVOR_PROFILE_ID: self.flavor_profile_id}

        # Happy path
        flavor = self.lb_admin_flavor_client.create_flavor(**flavor_kwargs)
        self.addCleanup(self.lb_admin_flavor_client.cleanup_a_flavor,
                        flavor[const.ID])

        # Test that a user without the load balancer role cannot
        # show flavor details.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = [
                'os_admin', 'os_primary', 'os_roles_lb_admin',
                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_primary', 'os_system_admin',
                                'os_system_reader', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = [
                'os_system_admin', 'os_system_reader', 'os_roles_lb_admin',
                'os_roles_lb_observer', 'os_roles_lb_global_observer',
                'os_roles_lb_member', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'FlavorClient', 'show_flavor', expected_allowed,
                flavor[const.ID])

        result = self.mem_flavor_client.show_flavor(flavor[const.ID])

        self.assertEqual(flavor[const.ID], result[const.ID])
        self.assertEqual(flavor_name, result[const.NAME])
        self.assertEqual(flavor_description, result[const.DESCRIPTION])
        self.assertTrue(result[const.ENABLED])
        self.assertEqual(self.flavor_profile_id,
                         result[const.FLAVOR_PROFILE_ID])

    @decorators.idempotent_id('3d9e2820-a68e-4db9-bf94-53cbcff2dc15')
    def test_flavor_update(self):
        """Tests flavor update API.

        * Create a fully populated flavor.
        * Show flavor details.
        * Validate the show reflects the initial values.
        * Validates that non-admin accounts cannot update the flavor.
        * Update the flavor details.
        * Show flavor details.
        * Validate the show reflects the updated values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavors are only available on '
                                     'Octavia API version 2.6 or newer.')
        flavor_name = data_utils.rand_name("lb_admin_flavor-update")
        flavor_description = data_utils.arbitrary_string(size=255)

        flavor_kwargs = {
            const.NAME: flavor_name,
            const.DESCRIPTION: flavor_description,
            const.ENABLED: True,
            const.FLAVOR_PROFILE_ID: self.flavor_profile_id}

        # Happy path
        flavor = self.lb_admin_flavor_client.create_flavor(**flavor_kwargs)
        self.addCleanup(self.lb_admin_flavor_client.cleanup_a_flavor,
                        flavor[const.ID])

        flavor_name2 = data_utils.rand_name("lb_admin_flavor-update-2")
        flavor_description2 = data_utils.arbitrary_string(size=255)
        flavor_updated_kwargs = {
            const.NAME: flavor_name2,
            const.DESCRIPTION: flavor_description2,
            const.ENABLED: False}

        # Test that a user without the load balancer role cannot
        # update flavor details.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'FlavorClient', 'update_flavor', expected_allowed, None, None,
                flavor[const.ID], **flavor_updated_kwargs)

        updated_flavor = self.lb_admin_flavor_client.update_flavor(
            flavor[const.ID], **flavor_updated_kwargs)

        self.assertEqual(flavor[const.ID], updated_flavor[const.ID])
        self.assertEqual(flavor_name2, updated_flavor[const.NAME])
        self.assertEqual(flavor_description2,
                         updated_flavor[const.DESCRIPTION])
        self.assertEqual(flavor[const.FLAVOR_PROFILE_ID],
                         updated_flavor[const.FLAVOR_PROFILE_ID])
        self.assertFalse(updated_flavor[const.ENABLED])

        result = self.mem_flavor_client.show_flavor(flavor[const.ID])

        self.assertEqual(flavor[const.ID], result[const.ID])
        self.assertEqual(flavor_name2, result[const.NAME])
        self.assertEqual(flavor_description2,
                         result[const.DESCRIPTION])
        self.assertEqual(flavor[const.FLAVOR_PROFILE_ID],
                         result[const.FLAVOR_PROFILE_ID])
        self.assertFalse(result[const.ENABLED])

    @decorators.idempotent_id('dfe9173a-26f3-4bba-9e69-d2b817ff2b86')
    def test_flavor_delete(self):
        """Tests flavor create and delete APIs.

        * Creates a flavor.
        * Validates that other accounts cannot delete the flavor.
        * Deletes the flavor.
        * Validates the flavor no longer exists.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavors are only available on '
                                     'Octavia API version 2.6 or newer.')
        flavor_name = data_utils.rand_name("lb_admin_flavor-delete")
        flavor_description = data_utils.arbitrary_string(size=255)

        flavor_kwargs = {
            const.NAME: flavor_name,
            const.DESCRIPTION: flavor_description,
            const.ENABLED: True,
            const.FLAVOR_PROFILE_ID: self.flavor_profile_id}

        # Happy path
        flavor = self.lb_admin_flavor_client.create_flavor(**flavor_kwargs)
        self.addCleanup(self.lb_admin_flavor_client.cleanup_a_flavor,
                        flavor[const.ID])

        # Test that a user without the load balancer admin role cannot
        # delete a flavor.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_delete_RBAC_enforcement(
                'FlavorClient', 'delete_flavor', expected_allowed,
                None, None, flavor[const.ID])

        # Happy path
        self.lb_admin_flavor_client.delete_flavor(flavor[const.ID])

        self.assertRaises(exceptions.NotFound,
                          self.lb_admin_flavor_client.show_flavor,
                          flavor[const.ID])
