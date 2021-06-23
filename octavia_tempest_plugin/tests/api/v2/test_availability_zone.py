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

from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base

CONF = config.CONF


class AvailabilityZoneAPITest(test_base.LoadBalancerBaseTest):
    """Test the availability zone object API."""

    @classmethod
    def skip_checks(cls):
        super(AvailabilityZoneAPITest, cls).skip_checks()
        if (CONF.load_balancer.availability_zone is None and
                not CONF.load_balancer.test_with_noop):
            raise cls.skipException(
                'Availability Zone API tests require an availability zone '
                'configured in the [load_balancer] availability_zone setting.')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(AvailabilityZoneAPITest, cls).resource_setup()

        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not (cls.lb_admin_availability_zone_profile_client
                .is_version_supported(cls.api_version, '2.14')):
            return

        # Create a shared availability zone profile
        availability_zone_profile_name = data_utils.rand_name(
            "lb_admin_availabilityzoneprofile-setup")
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

        cls.availability_zone_profile = (
            cls.lb_admin_availability_zone_profile_client
            .create_availability_zone_profile(
                **availability_zone_profile_kwargs))
        cls.addClassResourceCleanup(
            cls.lb_admin_availability_zone_profile_client
            .cleanup_availability_zone_profile,
            cls.availability_zone_profile[const.ID])
        cls.availability_zone_profile_id = (
            cls.availability_zone_profile[const.ID])

    @decorators.idempotent_id('3899ef15-37c3-48a3-807f-8bb10bd295f0')
    def test_availability_zone_create(self):
        """Tests availability zone create and basic show APIs.

        * Tests that users without the loadbalancer admin role cannot
          create an availability zone.
        * Create a fully populated availability zone.
        * Validate the response reflects the requested values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_availability_zone_client.is_version_supported(
                self.api_version, '2.14'):
            raise self.skipException('Availability zones are only available '
                                     'on Octavia API version 2.14 or newer.')
        availability_zone_name = data_utils.rand_name(
            "lb_admin_availability_zone-create")
        availability_zone_description = data_utils.arbitrary_string(size=255)

        availability_zone_kwargs = {
            const.NAME: availability_zone_name,
            const.DESCRIPTION: availability_zone_description,
            const.ENABLED: True,
            const.AVAILABILITY_ZONE_PROFILE_ID:
                self.availability_zone_profile_id}

        # Test that a user without the load balancer admin role cannot
        # create an availability zone.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'AvailabilityZoneClient', 'create_availability_zone',
                expected_allowed, **availability_zone_kwargs)

        # Happy path
        availability_zone = (
            self.lb_admin_availability_zone_client
                .create_availability_zone(**availability_zone_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_client
                .cleanup_an_availability_zone,
            availability_zone[const.NAME])

        self.assertEqual(availability_zone_name, availability_zone[const.NAME])
        self.assertEqual(availability_zone_description,
                         availability_zone[const.DESCRIPTION])
        self.assertTrue(availability_zone[const.ENABLED])
        self.assertEqual(self.availability_zone_profile_id,
                         availability_zone[const.AVAILABILITY_ZONE_PROFILE_ID])

        # Test that availability_zones do not support tags
        availability_zone_tags = ["Hello", "World"]
        tags_availability_zone_kwargs = availability_zone_kwargs.copy()
        tags_availability_zone_kwargs[const.TAGS] = availability_zone_tags
        self.assertRaises(
            TypeError,
            self.lb_admin_availability_zone_client.create_availability_zone,
            **tags_availability_zone_kwargs)

    @decorators.idempotent_id('bba84c0c-2832-4c4c-90ff-d28acfe4ae36')
    def test_availability_zone_list(self):
        """Tests availability zone list API and field filtering.

        * Create three availability zones.
        * Validates that non-admin accounts cannot list the availability zones.
        * List the availability zones using the default sort order.
        * List the availability zones using descending sort order.
        * List the availability zones using ascending sort order.
        * List the availability zones returning one field at a time.
        * List the availability zones returning two fields.
        * List the availability zones filtering to one of the three.
        * List the availability zones filtered, one field, and sorted.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_availability_zone_client.is_version_supported(
                self.api_version, '2.14'):
            raise self.skipException('Availability zones are only available '
                                     'on Octavia API version 2.14 or newer.')

        # Create availability zone 1
        az1_name = data_utils.rand_name("lb_admin_availability_zone-list-1")
        az1_description = 'A'

        az1_kwargs = {
            const.NAME: az1_name,
            const.DESCRIPTION: az1_description,
            const.ENABLED: True,
            const.AVAILABILITY_ZONE_PROFILE_ID:
                self.availability_zone_profile_id}

        az1 = (self.lb_admin_availability_zone_client
               .create_availability_zone(**az1_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_client
                .cleanup_an_availability_zone,
            az1[const.NAME])

        # Create availability zone 2
        az2_name = data_utils.rand_name("lb_admin_availability_zone-list-2")
        az2_description = 'B'

        az2_kwargs = {
            const.NAME: az2_name,
            const.DESCRIPTION: az2_description,
            const.ENABLED: False,
            const.AVAILABILITY_ZONE_PROFILE_ID:
                self.availability_zone_profile_id}

        az2 = (self.lb_admin_availability_zone_client
               .create_availability_zone(**az2_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_client
                .cleanup_an_availability_zone,
            az2[const.NAME])

        # Create availability zone 3
        az3_name = data_utils.rand_name("lb_admin_availability_zone-list-3")
        az3_description = 'C'

        az3_kwargs = {
            const.NAME: az3_name,
            const.DESCRIPTION: az3_description,
            const.ENABLED: True,
            const.AVAILABILITY_ZONE_PROFILE_ID:
                self.availability_zone_profile_id}

        az3 = (self.lb_admin_availability_zone_client
               .create_availability_zone(**az3_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_client
                .cleanup_an_availability_zone,
            az3[const.NAME])

        # default sort order (by Name) reference list
        ref_id_list_asc = [az1[const.NAME], az2[const.NAME],
                           az3[const.NAME]]
        ref_id_list_dsc = copy.deepcopy(ref_id_list_asc)
        ref_id_list_asc.sort()
        ref_id_list_dsc.sort(reverse=True)

        # Test that a user without the load balancer role cannot
        # list availability zones.
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
                'AvailabilityZoneClient', 'list_availability_zones',
                expected_allowed)

        # Check the default sort order (by ID)
        availability_zones = (
            self.mem_availability_zone_client.list_availability_zones())
        # Remove availability zones not used in this test
        availability_zones = [
            az for az in availability_zones
            if 'lb_admin_availability_zone-list' in az[const.NAME]]
        self.assertEqual(3, len(availability_zones))
        self.assertEqual(ref_id_list_asc[0], availability_zones[0][const.NAME])
        self.assertEqual(ref_id_list_asc[1], availability_zones[1][const.NAME])
        self.assertEqual(ref_id_list_asc[2], availability_zones[2][const.NAME])

        # Check the descending sort order by name
        availability_zones = (
            self.lb_admin_availability_zone_client.list_availability_zones(
                query_params='{sort}={name}:{order}'.format(
                    sort=const.SORT, name=const.NAME, order=const.DESC)))
        # Remove availability zones not used in this test
        availability_zones = [
            az for az in availability_zones
            if 'lb_admin_availability_zone-list' in az[const.NAME]]
        self.assertEqual(3, len(availability_zones))
        self.assertEqual(az3_name, availability_zones[0][const.NAME])
        self.assertEqual(az2_name, availability_zones[1][const.NAME])
        self.assertEqual(az1_name, availability_zones[2][const.NAME])

        # Check the ascending sort order by name
        availability_zones = (
            self.mem_availability_zone_client.list_availability_zones(
                query_params='{sort}={name}:{order}'.format(
                    sort=const.SORT, name=const.NAME, order=const.ASC)))
        # Remove availability zones not used in this test
        availability_zones = [
            az for az in availability_zones
            if 'lb_admin_availability_zone-list' in az[const.NAME]]
        self.assertEqual(3, len(availability_zones))
        self.assertEqual(az1_name, availability_zones[0][const.NAME])
        self.assertEqual(az2_name, availability_zones[1][const.NAME])
        self.assertEqual(az3_name, availability_zones[2][const.NAME])

        ref_availability_zones = [az1, az2, az3]
        sorted_availability_zones = sorted(ref_availability_zones,
                                           key=itemgetter(const.NAME))
        sorted_enabled_availability_zones = [
            az for az in sorted_availability_zones
            if az[const.ENABLED]]

        # Test fields
        for field in const.SHOW_AVAILABILITY_ZONE_FIELDS:
            availability_zones = (
                self.mem_availability_zone_client
                    .list_availability_zones(
                        query_params='{fields}={field}&{fields}={name}'.format(
                            fields=const.FIELDS, field=field, name=const.NAME))
            )
            # Remove availability zones not used in this test
            availability_zones = [
                az for az in availability_zones
                if 'lb_admin_availability_zone-list' in az[const.NAME]]
            self.assertEqual(3, len(availability_zones))
            self.assertEqual(sorted_availability_zones[0][field],
                             availability_zones[0][field])
            self.assertEqual(sorted_availability_zones[1][field],
                             availability_zones[1][field])
            self.assertEqual(sorted_availability_zones[2][field],
                             availability_zones[2][field])

        # Test filtering
        availability_zone = (
            self.mem_availability_zone_client.list_availability_zones(
                query_params='{name}={az_name}'.format(
                    name=const.NAME, az_name=az2[const.NAME])))
        self.assertEqual(1, len(availability_zone))
        self.assertEqual(az2[const.NAME], availability_zone[0][const.NAME])

        # Test combined params
        availability_zones = (
            self.mem_availability_zone_client.list_availability_zones(
                query_params='{enabled}={enable}&{fields}={name}&'
                             '{sort}={ID}:{desc}'.format(
                                 enabled=const.ENABLED,
                                 enable=True,
                                 fields=const.FIELDS, name=const.NAME,
                                 sort=const.SORT, ID=const.NAME,
                                 desc=const.DESC)))
        # Remove availability zones not used in this test
        availability_zones = [
            az for az in availability_zones
            if 'lb_admin_availability_zone-list' in az[const.NAME]]
        self.assertEqual(2, len(availability_zones))
        self.assertEqual(1, len(availability_zones[0]))
        self.assertEqual(sorted_enabled_availability_zones[1][const.NAME],
                         availability_zones[0][const.NAME])
        self.assertEqual(sorted_enabled_availability_zones[0][const.NAME],
                         availability_zones[1][const.NAME])

    @decorators.idempotent_id('4fa77f96-ba75-4255-bef8-6710cd7cb762')
    def test_availability_zone_show(self):
        """Tests availability zone show API.

        * Create a fully populated availability zone.
        * Validate that non-lb-admin accounts cannot see the availability zone.
        * Show availability zone details.
        * Validate the show reflects the requested values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_availability_zone_client.is_version_supported(
                self.api_version, '2.14'):
            raise self.skipException('Availability zones are only available '
                                     'on Octavia API version 2.14 or newer.')
        availability_zone_name = data_utils.rand_name(
            "lb_admin_availability_zone-show")
        availability_zone_description = data_utils.arbitrary_string(size=255)

        availability_zone_kwargs = {
            const.NAME: availability_zone_name,
            const.DESCRIPTION: availability_zone_description,
            const.ENABLED: True,
            const.AVAILABILITY_ZONE_PROFILE_ID:
                self.availability_zone_profile_id}

        # Happy path
        availability_zone = (
            self.lb_admin_availability_zone_client
                .create_availability_zone(**availability_zone_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_client
                .cleanup_an_availability_zone,
            availability_zone[const.NAME])

        # Test that a user without the load balancer role cannot
        # show availability zone details.
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
                'AvailabilityZoneClient', 'show_availability_zone',
                expected_allowed, availability_zone[const.NAME])

        result = self.mem_availability_zone_client.show_availability_zone(
            availability_zone[const.NAME])

        self.assertEqual(availability_zone_name, result[const.NAME])
        self.assertEqual(availability_zone_description,
                         result[const.DESCRIPTION])
        self.assertTrue(result[const.ENABLED])
        self.assertEqual(self.availability_zone_profile_id,
                         result[const.AVAILABILITY_ZONE_PROFILE_ID])

    @decorators.idempotent_id('9c466b9f-b70a-456d-9172-eb79b7820c7f')
    def test_availability_zone_update(self):
        """Tests availability zone update API.

        * Create a fully populated availability zone.
        * Show availability zone details.
        * Validate the show reflects the initial values.
        * Validate that non-admin accounts cannot update the availability zone.
        * Update the availability zone details.
        * Show availability zone details.
        * Validate the show reflects the updated values.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_availability_zone_client.is_version_supported(
                self.api_version, '2.14'):
            raise self.skipException('Availability zones are only available '
                                     'on Octavia API version 2.14 or newer.')
        availability_zone_name = data_utils.rand_name(
            "lb_admin_availability_zone-update")
        availability_zone_description = data_utils.arbitrary_string(size=255)

        availability_zone_kwargs = {
            const.NAME: availability_zone_name,
            const.DESCRIPTION: availability_zone_description,
            const.ENABLED: True,
            const.AVAILABILITY_ZONE_PROFILE_ID:
                self.availability_zone_profile_id}

        # Happy path
        availability_zone = (
            self.lb_admin_availability_zone_client
                .create_availability_zone(**availability_zone_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_client
                .cleanup_an_availability_zone,
            availability_zone[const.NAME])

        availability_zone_description2 = data_utils.arbitrary_string(size=255)
        availability_zone_updated_kwargs = {
            const.DESCRIPTION: availability_zone_description2,
            const.ENABLED: False}

        # Test that a user without the load balancer role cannot
        # update availability zone details.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'AvailabilityZoneClient', 'update_availability_zone',
                expected_allowed, None, None, availability_zone[const.NAME],
                **availability_zone_updated_kwargs)

        updated_availability_zone = (
            self.lb_admin_availability_zone_client.update_availability_zone(
                availability_zone[const.NAME],
                **availability_zone_updated_kwargs))

        self.assertEqual(
            availability_zone[const.NAME],
            updated_availability_zone[const.NAME])
        self.assertEqual(
            availability_zone_description2,
            updated_availability_zone[const.DESCRIPTION])
        self.assertEqual(
            availability_zone[const.AVAILABILITY_ZONE_PROFILE_ID],
            updated_availability_zone[const.AVAILABILITY_ZONE_PROFILE_ID])
        self.assertFalse(updated_availability_zone[const.ENABLED])

        result = (
            self.mem_availability_zone_client
                .show_availability_zone(availability_zone[const.NAME]))

        self.assertEqual(availability_zone[const.NAME], result[const.NAME])
        self.assertEqual(availability_zone_description2,
                         result[const.DESCRIPTION])
        self.assertEqual(availability_zone[const.AVAILABILITY_ZONE_PROFILE_ID],
                         result[const.AVAILABILITY_ZONE_PROFILE_ID])
        self.assertFalse(result[const.ENABLED])

    @decorators.idempotent_id('11585b33-2689-4693-be3b-26b210bb7fc5')
    def test_availability_zone_delete(self):
        """Tests availability zone create and delete APIs.

        * Creates an availability zone.
        * Validates that other accounts cannot delete the availability zone.
        * Deletes the availability zone.
        * Validates the availability zone no longer exists.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_availability_zone_client.is_version_supported(
                self.api_version, '2.14'):
            raise self.skipException('Availability zones are only available '
                                     'on Octavia API version 2.14 or newer.')
        availability_zone_name = data_utils.rand_name(
            "lb_admin_availability_zone-delete")
        availability_zone_description = data_utils.arbitrary_string(size=255)

        availability_zone_kwargs = {
            const.NAME: availability_zone_name,
            const.DESCRIPTION: availability_zone_description,
            const.ENABLED: True,
            const.AVAILABILITY_ZONE_PROFILE_ID:
                self.availability_zone_profile_id}

        # Happy path
        availability_zone = (
            self.lb_admin_availability_zone_client
                .create_availability_zone(**availability_zone_kwargs))
        self.addCleanup(
            self.lb_admin_availability_zone_client
                .cleanup_an_availability_zone,
            availability_zone[const.NAME])

        # Test that a user without the load balancer admin role cannot
        # delete an availability zone.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_delete_RBAC_enforcement(
                'AvailabilityZoneClient', 'delete_availability_zone',
                expected_allowed, None, None, availability_zone[const.NAME])

        # Happy path
        self.lb_admin_availability_zone_client.delete_availability_zone(
            availability_zone[const.NAME])

        self.assertRaises(
            exceptions.NotFound,
            self.lb_admin_availability_zone_client.show_availability_zone,
            availability_zone[const.NAME])
