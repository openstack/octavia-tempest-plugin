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


class FlavorProfileAPITest(test_base.LoadBalancerBaseTest):
    """Test the flavor profile object API."""

    @decorators.idempotent_id('d0e3a08e-d58a-4460-83ed-34307ca04cde')
    def test_flavor_profile_create(self):
        """Tests flavor profile create and basic show APIs.

        * Tests that users without the loadbalancer admin role cannot
          create flavor profiles.
        * Create a fully populated flavor profile.
        * Validate the response reflects the requested values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_profile_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavor profiles are only available on '
                                     'Octavia API version 2.6 or newer.')

        flavor_profile_name = data_utils.rand_name(
            "lb_admin_flavorprofile1-create")
        flavor_data = {const.LOADBALANCER_TOPOLOGY: const.SINGLE}
        flavor_data_json = jsonutils.dumps(flavor_data)

        flavor_profile_kwargs = {
            const.NAME: flavor_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data_json
        }

        # Test that a user without the load balancer admin role cannot
        # create a flavor profile
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'FlavorProfileClient', 'create_flavor_profile',
                expected_allowed, None, None, **flavor_profile_kwargs)

        # Happy path
        flavor_profile = (
            self.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            flavor_profile[const.ID])

        UUID(flavor_profile[const.ID])
        self.assertEqual(flavor_profile_name, flavor_profile[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         flavor_profile[const.PROVIDER_NAME])
        self.assertEqual(flavor_data_json, flavor_profile[const.FLAVOR_DATA])

        # Testing that flavor_profiles do not support tags
        flavor_profile_tags = ["Hello", "World"]
        tags_flavor_profile_kwargs = flavor_profile_kwargs.copy()
        tags_flavor_profile_kwargs[const.TAGS] = flavor_profile_tags
        self.assertRaises(
            TypeError,
            self.lb_admin_flavor_profile_client.create_flavor_profile,
            **tags_flavor_profile_kwargs)

    @decorators.idempotent_id('c4e17fdf-849a-4132-93ae-dfca21ce4444')
    def test_flavor_profile_list(self):
        """Tests flavor profile list API and field filtering.

        * Create three flavor profiles.
        * Validates that non-admin accounts cannot list the flavor profiles.
        * List the flavor profiles using the default sort order.
        * List the flavor profiles using descending sort order.
        * List the flavor profiles using ascending sort order.
        * List the flavor profiles returning one field at a time.
        * List the flavor profiles returning two fields.
        * List the flavor profiles filtering to one of the three.
        * List the flavor profiles filtered, one field, and sorted.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_profile_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavor profiles are only available on '
                                     'Octavia API version 2.6 or newer.')

        # Create flavor profile 1
        flavor_profile1_name = data_utils.rand_name(
            "lb_admin_flavorprofile-list-1")
        flavor_data1 = {const.LOADBALANCER_TOPOLOGY: const.SINGLE}
        flavor_data1_json = jsonutils.dumps(flavor_data1)

        flavor_profile1_kwargs = {
            const.NAME: flavor_profile1_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data1_json
        }
        flavor_profile1 = (
            self.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile1_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            flavor_profile1[const.ID])

        # Create flavor profile 2
        flavor_profile2_name = data_utils.rand_name(
            "lb_admin_flavorprofile-list-2")
        flavor_data2 = {const.LOADBALANCER_TOPOLOGY: const.ACTIVE_STANDBY}
        flavor_data2_json = jsonutils.dumps(flavor_data2)

        flavor_profile2_kwargs = {
            const.NAME: flavor_profile2_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data2_json
        }
        flavor_profile2 = (
            self.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile2_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            flavor_profile2[const.ID])

        # Create flavor profile 3
        flavor_profile3_name = data_utils.rand_name(
            "lb_admin_flavorprofile-list-3")
        flavor_data3 = {const.LOADBALANCER_TOPOLOGY: const.SINGLE}
        flavor_data3_json = jsonutils.dumps(flavor_data3)

        flavor_profile3_kwargs = {
            const.NAME: flavor_profile3_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data3_json
        }
        flavor_profile3 = (
            self.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile3_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            flavor_profile3[const.ID])

        # default sort order (by ID) reference list
        ref_id_list_asc = [flavor_profile1[const.ID],
                           flavor_profile2[const.ID],
                           flavor_profile3[const.ID]]
        ref_id_list_dsc = copy.deepcopy(ref_id_list_asc)
        ref_id_list_asc.sort()
        ref_id_list_dsc.sort(reverse=True)

        # Test that a user without the load balancer admin role cannot
        # list flavor profiles.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'FlavorProfileClient', 'list_flavor_profiles',
                expected_allowed)

        # Check the default sort order (by ID)
        profiles = self.lb_admin_flavor_profile_client.list_flavor_profiles()
        # Remove flavor profiles not used in this test
        profiles = [prof for prof in profiles
                    if 'lb_admin_flavorprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(ref_id_list_asc[0], profiles[0][const.ID])
        self.assertEqual(ref_id_list_asc[1], profiles[1][const.ID])
        self.assertEqual(ref_id_list_asc[2], profiles[2][const.ID])

        # Check the descending sort order by name
        profiles = self.lb_admin_flavor_profile_client.list_flavor_profiles(
            query_params='{sort}={name}:{order}'.format(
                sort=const.SORT, name=const.NAME, order=const.DESC))
        # Remove flavor profiles not used in this test
        profiles = [prof for prof in profiles
                    if 'lb_admin_flavorprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(flavor_profile3_name, profiles[0][const.NAME])
        self.assertEqual(flavor_profile2_name, profiles[1][const.NAME])
        self.assertEqual(flavor_profile1_name, profiles[2][const.NAME])

        # Check the ascending sort order by name
        profiles = self.lb_admin_flavor_profile_client.list_flavor_profiles(
            query_params='{sort}={name}:{order}'.format(
                sort=const.SORT, name=const.NAME, order=const.ASC))
        # Remove flavor profiles not used in this test
        profiles = [prof for prof in profiles
                    if 'lb_admin_flavorprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(flavor_profile1_name, profiles[0][const.NAME])
        self.assertEqual(flavor_profile2_name, profiles[1][const.NAME])
        self.assertEqual(flavor_profile3_name, profiles[2][const.NAME])

        ref_profiles = [flavor_profile1, flavor_profile2, flavor_profile3]
        sorted_profiles = sorted(ref_profiles, key=itemgetter(const.ID))

        # Test fields
        flavor_profile_client = self.lb_admin_flavor_profile_client
        for field in const.SHOW_FLAVOR_PROFILE_FIELDS:
            profiles = flavor_profile_client.list_flavor_profiles(
                query_params='{fields}={field}&{fields}={name}'.format(
                    fields=const.FIELDS, field=field, name=const.NAME))
            # Remove flavor profiles not used in this test
            profiles = [prof for prof in profiles
                        if 'lb_admin_flavorprofile-list' in prof[const.NAME]]

            self.assertEqual(3, len(profiles))
            self.assertEqual(sorted_profiles[0][field], profiles[0][field])
            self.assertEqual(sorted_profiles[1][field], profiles[1][field])
            self.assertEqual(sorted_profiles[2][field], profiles[2][field])

        # Test filtering
        profile = self.lb_admin_flavor_profile_client.list_flavor_profiles(
            query_params='{name}={prof_name}'.format(
                name=const.NAME,
                prof_name=flavor_profile2[const.NAME]))
        self.assertEqual(1, len(profile))
        self.assertEqual(flavor_profile2[const.ID], profile[0][const.ID])

        # Test combined params
        profiles = self.lb_admin_flavor_profile_client.list_flavor_profiles(
            query_params='{provider_name}={provider}&{fields}={name}&'
                         '{sort}={ID}:{desc}'.format(
                             provider_name=const.PROVIDER_NAME,
                             provider=CONF.load_balancer.provider,
                             fields=const.FIELDS, name=const.NAME,
                             sort=const.SORT, ID=const.ID,
                             desc=const.DESC))
        # Remove flavor profiles not used in this test
        profiles = [prof for prof in profiles
                    if 'lb_admin_flavorprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(1, len(profiles[0]))
        self.assertEqual(sorted_profiles[2][const.NAME],
                         profiles[0][const.NAME])
        self.assertEqual(sorted_profiles[1][const.NAME],
                         profiles[1][const.NAME])
        self.assertEqual(sorted_profiles[0][const.NAME],
                         profiles[2][const.NAME])

    @decorators.idempotent_id('a2c2ff9a-fce1-42fd-8cfd-56dea31610f6')
    def test_flavor_profile_show(self):
        """Tests flavor profile show API.

        * Create a fully populated flavor profile.
        * Show flavor profile details.
        * Validate the show reflects the requested values.
        * Validates that non-lb-admin accounts cannot see the flavor profile.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_profile_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavor profiles are only available on '
                                     'Octavia API version 2.6 or newer.')

        flavor_profile_name = data_utils.rand_name(
            "lb_admin_flavorprofile1-show")
        flavor_data = {const.LOADBALANCER_TOPOLOGY: const.ACTIVE_STANDBY}
        flavor_data_json = jsonutils.dumps(flavor_data)

        flavor_profile_kwargs = {
            const.NAME: flavor_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data_json
        }

        flavor_profile = (
            self.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            flavor_profile[const.ID])

        # Test that a user without the load balancer admin role cannot
        # show a flavor profile.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'FlavorProfileClient', 'show_flavor_profile',
                expected_allowed, flavor_profile[const.ID])

        result = (
            self.lb_admin_flavor_profile_client.show_flavor_profile(
                flavor_profile[const.ID]))

        self.assertEqual(flavor_profile_name, result[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         result[const.PROVIDER_NAME])
        self.assertEqual(flavor_data_json, result[const.FLAVOR_DATA])

    @decorators.idempotent_id('32a2e285-8dfc-485f-a450-a4d450d3c3ec')
    def test_flavor_profile_update(self):
        """Tests flavor profile update API.

        * Create a fully populated flavor profile.
        * Show flavor profile details.
        * Validate the show reflects the initial values.
        * Validates that non-admin accounts cannot update the flavor profile.
        * Update the flavor profile details.
        * Show flavor profile details.
        * Validate the show reflects the updated values.
        """

        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_profile_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavor profiles are only available on '
                                     'Octavia API version 2.6 or newer.')

        flavor_profile_name = data_utils.rand_name(
            "lb_admin_flavorprofile1-update")
        flavor_data = {const.LOADBALANCER_TOPOLOGY: const.SINGLE}
        flavor_data_json = jsonutils.dumps(flavor_data)

        flavor_profile_kwargs = {
            const.NAME: flavor_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data_json
        }

        flavor_profile = (
            self.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            flavor_profile[const.ID])

        self.assertEqual(flavor_profile_name, flavor_profile[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         flavor_profile[const.PROVIDER_NAME])
        self.assertEqual(flavor_data_json, flavor_profile[const.FLAVOR_DATA])

        flavor_profile_name2 = data_utils.rand_name(
            "lb_admin_flavorprofile1-update2")
        flavor_data2 = {const.LOADBALANCER_TOPOLOGY: const.ACTIVE_STANDBY}
        flavor_data2_json = jsonutils.dumps(flavor_data2)

        # TODO(johnsom) Figure out a reliable second provider
        flavor_profile_updated_kwargs = {
            const.NAME: flavor_profile_name2,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data2_json
        }

        # Test that a user without the load balancer admin role cannot
        # update a flavor profile.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'FlavorProfileClient', 'update_flavor_profile',
                expected_allowed, None, None, flavor_profile[const.ID],
                **flavor_profile_updated_kwargs)

        result = self.lb_admin_flavor_profile_client.update_flavor_profile(
            flavor_profile[const.ID], **flavor_profile_updated_kwargs)

        self.assertEqual(flavor_profile_name2, result[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         result[const.PROVIDER_NAME])
        self.assertEqual(flavor_data2_json, result[const.FLAVOR_DATA])

        # Check that a show reflects the new values
        get_result = (
            self.lb_admin_flavor_profile_client.show_flavor_profile(
                flavor_profile[const.ID]))

        self.assertEqual(flavor_profile_name2, get_result[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         get_result[const.PROVIDER_NAME])
        self.assertEqual(flavor_data2_json, get_result[const.FLAVOR_DATA])

    @decorators.idempotent_id('4c2eaacf-c2c8-422a-b7dc-a30ceba6bcd4')
    def test_flavor_profile_delete(self):
        """Tests flavor profile create and delete APIs.

        * Creates a flavor profile.
        * Validates that other accounts cannot delete the flavor profile.
        * Deletes the flavor profile.
        * Validates the flavor profile is in the DELETED state.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_flavor_profile_client.is_version_supported(
                self.api_version, '2.6'):
            raise self.skipException('Flavor profiles are only available on '
                                     'Octavia API version 2.6 or newer.')

        flavor_profile_name = data_utils.rand_name(
            "lb_admin_flavorprofile1-delete")
        flavor_data = {const.LOADBALANCER_TOPOLOGY: const.SINGLE}
        flavor_data_json = jsonutils.dumps(flavor_data)

        flavor_profile_kwargs = {
            const.NAME: flavor_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.FLAVOR_DATA: flavor_data_json
        }

        flavor_profile = (
            self.lb_admin_flavor_profile_client.create_flavor_profile(
                **flavor_profile_kwargs))
        self.addCleanup(
            self.lb_admin_flavor_profile_client.cleanup_flavor_profile,
            flavor_profile[const.ID])

        # Test that a user without the load balancer admin role cannot
        # delete a flavor profile
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_delete_RBAC_enforcement(
                'FlavorProfileClient', 'delete_flavor_profile',
                expected_allowed, None, None, flavor_profile[const.ID])

        # Happy path
        self.lb_admin_flavor_profile_client.delete_flavor_profile(
            flavor_profile[const.ID])

        self.assertRaises(
            exceptions.NotFound,
            self.lb_admin_flavor_profile_client.show_flavor_profile,
            flavor_profile[const.ID])
