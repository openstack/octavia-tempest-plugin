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
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base

CONF = config.CONF


class AvailabilityZoneProfileAPITest(test_base.LoadBalancerBaseTest):
    """Test the availability zone profile object API."""

    @classmethod
    def skip_checks(cls):
        super(AvailabilityZoneProfileAPITest, cls).skip_checks()
        if (CONF.load_balancer.availability_zone is None and
                not CONF.load_balancer.test_with_noop):
            raise cls.skipException(
                'Availability zone profile API tests require an availability '
                'zone configured in the [load_balancer] availability_zone '
                'setting in the tempest configuration file.')

    @decorators.idempotent_id('e512b580-ef32-44c3-bbd2-efdc27ba2ea6')
    def test_availability_zone_profile_create(self):
        """Tests availability zone profile create and basic show APIs.

        * Tests that users without the loadbalancer admin role cannot
          create availability zone profiles.
        * Create a fully populated availability zone profile.
        * Validate the response reflects the requested values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not (
                self.lb_admin_availability_zone_profile_client
                    .is_version_supported(self.api_version, '2.14')):
            raise self.skipException(
                'Availability zone profiles are only available on '
                'Octavia API version 2.14 or newer.')

        availability_zone_profile_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile1-create")
        availability_zone_data = {
            const.COMPUTE_ZONE: CONF.load_balancer.availability_zone,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data_json = jsonutils.dumps(availability_zone_data)

        availability_zone_profile_kwargs = {
            const.NAME: availability_zone_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data_json
        }

        # Test that a user without the load balancer admin role cannot
        # create an availability zone profile.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'AvailabilityZoneProfileClient',
                'create_availability_zone_profile',
                expected_allowed, **availability_zone_profile_kwargs)

        # Happy path
        availability_zone_profile = (
            self.lb_admin_availability_zone_profile_client
                .create_availability_zone_profile(
                    **availability_zone_profile_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_profile_client
                .cleanup_availability_zone_profile,
            availability_zone_profile[const.ID])

        UUID(availability_zone_profile[const.ID])
        self.assertEqual(
            availability_zone_profile_name,
            availability_zone_profile[const.NAME])
        self.assertEqual(
            CONF.load_balancer.provider,
            availability_zone_profile[const.PROVIDER_NAME])
        self.assertEqual(
            availability_zone_data_json,
            availability_zone_profile[const.AVAILABILITY_ZONE_DATA])

        # Testing that availability_zone_profiles do not support tags
        availability_zone_profile_tags = ["Hello", "World"]
        tags_availability_zone_profile_kwargs = (
            availability_zone_profile_kwargs.copy())
        tags_availability_zone_profile_kwargs[const.TAGS] = (
            availability_zone_profile_tags)
        az_profile_client = self.lb_admin_availability_zone_profile_client
        self.assertRaises(TypeError,
                          az_profile_client.create_availability_zone_profile,
                          **tags_availability_zone_profile_kwargs)

    @decorators.idempotent_id('ef7d1c45-e312-46ce-8dcb-f2fe26295658')
    def test_availability_zone_profile_list(self):
        """Tests availability zone profile list API and field filtering.

        * Create three availability zone profiles.
        * Validates that non-admin accounts cannot list the availability zone
          profiles.
        * List the availability zone profiles using the default sort order.
        * List the availability zone profiles using descending sort order.
        * List the availability zone profiles using ascending sort order.
        * List the availability zone profiles returning one field at a time.
        * List the availability zone profiles returning two fields.
        * List the availability zone profiles filtering to one of the three.
        * List the availability zone profiles filtered, one field, and sorted.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not (self.lb_admin_availability_zone_profile_client
                .is_version_supported(self.api_version, '2.14')):
            raise self.skipException(
                'Availability zone profiles are only available on '
                'Octavia API version 2.14 or newer.')
        if ((CONF.load_balancer.availability_zone2 is None or
             CONF.load_balancer.availability_zone3 is None) and
                not CONF.load_balancer.test_with_noop):
            raise self.skipException(
                'Availability zone profile list API test requires the '
                '[load_balancer] availability_zone, availability_zone2, and '
                'availability_zone3 settings be defined in the tempest '
                'configuration file.')

        # Create availability zone profile 1
        availability_zone_profile1_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile-list-1")
        availability_zone_data1 = {
            const.COMPUTE_ZONE: CONF.load_balancer.availability_zone,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data1_json = jsonutils.dumps(availability_zone_data1)

        availability_zone_profile1_kwargs = {
            const.NAME: availability_zone_profile1_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data1_json
        }
        availability_zone_profile1 = (
            self.lb_admin_availability_zone_profile_client
                .create_availability_zone_profile(
                    **availability_zone_profile1_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_profile_client
                .cleanup_availability_zone_profile,
            availability_zone_profile1[const.ID])

        # Create availability zone profile 2
        availability_zone_profile2_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile-list-2")
        availability_zone_data2 = {
            const.COMPUTE_ZONE: CONF.load_balancer.availability_zone2,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data2_json = jsonutils.dumps(availability_zone_data2)

        availability_zone_profile2_kwargs = {
            const.NAME: availability_zone_profile2_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data2_json
        }
        availability_zone_profile2 = (
            self.lb_admin_availability_zone_profile_client
                .create_availability_zone_profile(
                    **availability_zone_profile2_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_profile_client
                .cleanup_availability_zone_profile,
            availability_zone_profile2[const.ID])

        # Create availability zone profile 3
        availability_zone_profile3_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile-list-3")
        availability_zone_data3 = {
            const.COMPUTE_ZONE: CONF.load_balancer.availability_zone3,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data3_json = jsonutils.dumps(availability_zone_data3)

        availability_zone_profile3_kwargs = {
            const.NAME: availability_zone_profile3_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data3_json
        }
        availability_zone_profile3 = (
            self.lb_admin_availability_zone_profile_client
                .create_availability_zone_profile(
                    **availability_zone_profile3_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_profile_client
                .cleanup_availability_zone_profile,
            availability_zone_profile3[const.ID])

        # default sort order (by ID) reference list
        ref_id_list_asc = [availability_zone_profile1[const.ID],
                           availability_zone_profile2[const.ID],
                           availability_zone_profile3[const.ID]]
        ref_id_list_dsc = copy.deepcopy(ref_id_list_asc)
        ref_id_list_asc.sort()
        ref_id_list_dsc.sort(reverse=True)

        # Test that a user without the load balancer admin role cannot
        # list availability zone profiles.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'AvailabilityZoneProfileClient',
                'list_availability_zone_profiles', expected_allowed)

        # Check the default sort order (by ID)
        profiles = (self.lb_admin_availability_zone_profile_client
                    .list_availability_zone_profiles())
        # Remove availability zone profiles not used in this test
        profiles = [
            prof for prof in profiles
            if 'lb_admin_availabilityzoneprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(ref_id_list_asc[0], profiles[0][const.ID])
        self.assertEqual(ref_id_list_asc[1], profiles[1][const.ID])
        self.assertEqual(ref_id_list_asc[2], profiles[2][const.ID])

        # Check the descending sort order by name
        profiles = (
            self.lb_admin_availability_zone_profile_client
            .list_availability_zone_profiles(
                query_params='{sort}={name}:{order}'.format(
                    sort=const.SORT, name=const.NAME, order=const.DESC)))
        # Remove availability zone profiles not used in this test
        profiles = [
            prof for prof in profiles
            if 'lb_admin_availabilityzoneprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(availability_zone_profile3_name,
                         profiles[0][const.NAME])
        self.assertEqual(availability_zone_profile2_name,
                         profiles[1][const.NAME])
        self.assertEqual(availability_zone_profile1_name,
                         profiles[2][const.NAME])

        # Check the ascending sort order by name
        profiles = (
            self.lb_admin_availability_zone_profile_client
            .list_availability_zone_profiles(
                query_params='{sort}={name}:{order}'.format(
                    sort=const.SORT, name=const.NAME, order=const.ASC)))
        # Remove availability zone profiles not used in this test
        profiles = [
            prof for prof in profiles
            if 'lb_admin_availabilityzoneprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(availability_zone_profile1_name,
                         profiles[0][const.NAME])
        self.assertEqual(availability_zone_profile2_name,
                         profiles[1][const.NAME])
        self.assertEqual(availability_zone_profile3_name,
                         profiles[2][const.NAME])

        ref_profiles = [availability_zone_profile1, availability_zone_profile2,
                        availability_zone_profile3]
        sorted_profiles = sorted(ref_profiles, key=itemgetter(const.ID))

        # Test fields
        availability_zone_profile_client = (
            self.lb_admin_availability_zone_profile_client)
        for field in const.SHOW_AVAILABILITY_ZONE_PROFILE_FIELDS:
            profiles = (
                availability_zone_profile_client
                .list_availability_zone_profiles(
                    query_params='{fields}={field}&{fields}={name}'.format(
                        fields=const.FIELDS, field=field, name=const.NAME)))
            # Remove availability zone profiles not used in this test
            profiles = [
                prof for prof in profiles
                if 'lb_admin_availabilityzoneprofile-list' in prof[const.NAME]]

            self.assertEqual(3, len(profiles))
            self.assertEqual(sorted_profiles[0][field], profiles[0][field])
            self.assertEqual(sorted_profiles[1][field], profiles[1][field])
            self.assertEqual(sorted_profiles[2][field], profiles[2][field])

        # Test filtering
        profile = (
            self.lb_admin_availability_zone_profile_client
            .list_availability_zone_profiles(
                query_params='{name}={prof_name}'.format(
                    name=const.NAME,
                    prof_name=availability_zone_profile2[const.NAME])))
        self.assertEqual(1, len(profile))
        self.assertEqual(availability_zone_profile2[const.ID],
                         profile[0][const.ID])

        # Test combined params
        profiles = (
            self.lb_admin_availability_zone_profile_client
            .list_availability_zone_profiles(
                query_params='{provider_name}={provider}&{fields}={name}&'
                             '{sort}={ID}:{desc}'.format(
                                 provider_name=const.PROVIDER_NAME,
                                 provider=CONF.load_balancer.provider,
                                 fields=const.FIELDS, name=const.NAME,
                                 sort=const.SORT, ID=const.ID,
                                 desc=const.DESC)))
        # Remove availability zone profiles not used in this test
        profiles = [
            prof for prof in profiles
            if 'lb_admin_availabilityzoneprofile-list' in prof[const.NAME]]
        self.assertEqual(3, len(profiles))
        self.assertEqual(1, len(profiles[0]))
        self.assertEqual(sorted_profiles[2][const.NAME],
                         profiles[0][const.NAME])
        self.assertEqual(sorted_profiles[1][const.NAME],
                         profiles[1][const.NAME])
        self.assertEqual(sorted_profiles[0][const.NAME],
                         profiles[2][const.NAME])

    @decorators.idempotent_id('379d92dc-7f6d-4674-ae6f-b3aa2120c677')
    def test_availability_zone_profile_show(self):
        """Tests availability zone profile show API.

        * Create a fully populated availability zone profile.
        * Show availability zone profile details.
        * Validate the show reflects the requested values.
        * Validates that non-lb-admin accounts cannot see the availability zone
          profile.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not (self.lb_admin_availability_zone_profile_client
                .is_version_supported(self.api_version, '2.14')):
            raise self.skipException(
                'Availability zone profiles are only available on '
                'Octavia API version 2.14 or newer.')

        availability_zone_profile_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile1-show")
        availability_zone_data = {
            const.COMPUTE_ZONE: CONF.load_balancer.availability_zone,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data_json = jsonutils.dumps(availability_zone_data)

        availability_zone_profile_kwargs = {
            const.NAME: availability_zone_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data_json
        }

        availability_zone_profile = (
            self.lb_admin_availability_zone_profile_client
                .create_availability_zone_profile(
                    **availability_zone_profile_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_profile_client
                .cleanup_availability_zone_profile,
            availability_zone_profile[const.ID])

        # Test that a user without the load balancer admin role cannot
        # show an availability zone profile
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'AvailabilityZoneProfileClient',
                'show_availability_zone_profile', expected_allowed,
                availability_zone_profile[const.ID])

        result = (
            self.lb_admin_availability_zone_profile_client
                .show_availability_zone_profile(
                    availability_zone_profile[const.ID]))

        self.assertEqual(availability_zone_profile_name, result[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         result[const.PROVIDER_NAME])
        self.assertEqual(availability_zone_data_json,
                         result[const.AVAILABILITY_ZONE_DATA])

    @decorators.idempotent_id('7121d4c0-f751-4b4e-a4c1-ab06c27a54a4')
    def test_availability_zone_profile_update(self):
        """Tests availability zone profile update API.

        * Create a fully populated availability zone profile.
        * Show availability zone profile details.
        * Validate the show reflects the initial values.
        * Validates that non-admin accounts cannot update the availability zone
          profile.
        * Update the availability zone profile details.
        * Show availability zone profile details.
        * Validate the show reflects the updated values.
        """

        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not (self.lb_admin_availability_zone_profile_client
                .is_version_supported(self.api_version, '2.14')):
            raise self.skipException(
                'Availability zone profiles are only available on '
                'Octavia API version 2.14 or newer.')
        if (CONF.load_balancer.availability_zone2 is None and
                not CONF.load_balancer.test_with_noop):
            raise self.skipException(
                'Availability zone profile update API tests requires '
                '[load_balancer] availability_zone2 to be defined in the '
                'tempest configuration file.')

        availability_zone_profile_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile1-update")
        availability_zone_data = {
            const.COMPUTE_ZONE: CONF.load_balancer.availability_zone,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data_json = jsonutils.dumps(availability_zone_data)

        availability_zone_profile_kwargs = {
            const.NAME: availability_zone_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data_json
        }

        availability_zone_profile = (
            self.lb_admin_availability_zone_profile_client
                .create_availability_zone_profile(
                    **availability_zone_profile_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_profile_client
                .cleanup_availability_zone_profile,
            availability_zone_profile[const.ID])

        self.assertEqual(
            availability_zone_profile_name,
            availability_zone_profile[const.NAME])
        self.assertEqual(
            CONF.load_balancer.provider,
            availability_zone_profile[const.PROVIDER_NAME])
        self.assertEqual(
            availability_zone_data_json,
            availability_zone_profile[const.AVAILABILITY_ZONE_DATA])

        availability_zone_profile_name2 = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile1-update2")
        availability_zone_data2 = {
            const.COMPUTE_ZONE:  CONF.load_balancer.availability_zone2,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data2_json = jsonutils.dumps(availability_zone_data2)

        # TODO(johnsom) Figure out a reliable second provider
        availability_zone_profile_updated_kwargs = {
            const.NAME: availability_zone_profile_name2,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data2_json
        }

        # Test that a user without the load balancer admin role cannot
        # update an availability zone profile.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'AvailabilityZoneProfileClient',
                'update_availability_zone_profile', expected_allowed,
                None, None, availability_zone_profile[const.ID],
                **availability_zone_profile_updated_kwargs)

        result = (
            self.lb_admin_availability_zone_profile_client
            .update_availability_zone_profile(
                availability_zone_profile[const.ID],
                **availability_zone_profile_updated_kwargs))

        self.assertEqual(availability_zone_profile_name2, result[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         result[const.PROVIDER_NAME])
        self.assertEqual(availability_zone_data2_json,
                         result[const.AVAILABILITY_ZONE_DATA])

        # Check that a show reflects the new values
        get_result = (
            self.lb_admin_availability_zone_profile_client
                .show_availability_zone_profile(
                    availability_zone_profile[const.ID]))

        self.assertEqual(availability_zone_profile_name2,
                         get_result[const.NAME])
        self.assertEqual(CONF.load_balancer.provider,
                         get_result[const.PROVIDER_NAME])
        self.assertEqual(availability_zone_data2_json,
                         get_result[const.AVAILABILITY_ZONE_DATA])

    @decorators.idempotent_id('371cee1d-3404-4744-b5c5-8a3d37aa8425')
    def test_availability_zone_profile_delete(self):
        """Tests availability zone profile create and delete APIs.

        * Creates an availability zone profile profile.
        * Validates that other accounts cannot delete the availability zone
          profile.
        * Deletes the availability zone profile.
        * Validates the availability zone profile is in the DELETED state.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not (self.lb_admin_availability_zone_profile_client
                .is_version_supported(self.api_version, '2.14')):
            raise self.skipException(
                'Availability zone profiles are only available on '
                'Octavia API version 2.14 or newer.')

        availability_zone_profile_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile1-delete")
        availability_zone_data = {
            const.COMPUTE_ZONE: CONF.load_balancer.availability_zone,
            const.MANAGEMENT_NETWORK: uuidutils.generate_uuid(),
        }
        availability_zone_data_json = jsonutils.dumps(availability_zone_data)

        availability_zone_profile_kwargs = {
            const.NAME: availability_zone_profile_name,
            const.PROVIDER_NAME: CONF.load_balancer.provider,
            const.AVAILABILITY_ZONE_DATA: availability_zone_data_json
        }

        availability_zone_profile = (
            self.lb_admin_availability_zone_profile_client
                .create_availability_zone_profile(
                    **availability_zone_profile_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_profile_client
                .cleanup_availability_zone_profile,
            availability_zone_profile[const.ID])

        # Test that a user without the load balancer admin role cannot
        # delete an availability zone profile.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_delete_RBAC_enforcement(
                'AvailabilityZoneProfileClient',
                'delete_availability_zone_profile', expected_allowed,
                None, None, availability_zone_profile[const.ID])

        # Happy path
        (self.lb_admin_availability_zone_profile_client
            .delete_availability_zone_profile(
                availability_zone_profile[const.ID]))

        self.assertRaises(
            exceptions.NotFound,
            self.lb_admin_availability_zone_profile_client
                .show_availability_zone_profile,
            availability_zone_profile[const.ID])
