#    Copyright 2019 Rackspace US Inc.  All rights reserved.
#    Copyright 2019 Verizon Media
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

from tempest import config
from tempest.lib import decorators

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base

CONF = config.CONF


class AvailabilityZoneCapabilitiesAPITest(test_base.LoadBalancerBaseTest):
    """Test the provider availability zone capabilities API."""

    @decorators.idempotent_id('cb3e4c59-4114-420b-9837-2666d4d5fef4')
    def test_availability_zone_capabilities_list(self):
        """Tests provider availability zone capabilities list API/filtering.

        * Validates that non-lb admin accounts cannot list the capabilities.
        * List the availability zone capablilities.
        * Validate that the "loadbalancer_topology" capablility is present.
        * List the providers returning one field at a time.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.mem_provider_client.is_version_supported(
                self.api_version, '2.14'):
            raise self.skipException(
                'Availability zone capabilities are only available '
                'on Octavia API version 2.14 or newer.')

        # Test that a user without the load balancer admin role cannot
        # list provider availability zone capabilities.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'AvailabilityZoneCapabilitiesClient',
                'list_availability_zone_capabilities', expected_allowed,
                CONF.load_balancer.provider)

        # Check for an expected availability zone capability for the
        # configured provider
        admin_capabilities_client = (
            self.lb_admin_availability_zone_capabilities_client)
        capabilities = (
            admin_capabilities_client.list_availability_zone_capabilities(
                CONF.load_balancer.provider))

        expected_name = list(
            CONF.load_balancer.expected_availability_zone_capability)[0]
        expected_description = (
            CONF.load_balancer.expected_availability_zone_capability[
                expected_name])
        for capability in capabilities:
            if capability[const.NAME] == expected_name:
                self.assertEqual(expected_description,
                                 capability[const.DESCRIPTION])

        # Test fields
        capabilities = (
            admin_capabilities_client.list_availability_zone_capabilities(
                CONF.load_balancer.provider,
                query_params='{fields}={field}&{field}={exp_name}'.format(
                    fields=const.FIELDS, field=const.NAME,
                    exp_name=expected_name)))
        self.assertEqual(1, len(capabilities[0]))
        self.assertEqual(expected_name, capabilities[0][const.NAME])

        capabilities = (
            admin_capabilities_client.list_availability_zone_capabilities(
                CONF.load_balancer.provider,
                query_params='{fields}={field}&{name}={exp_name}'.format(
                    fields=const.FIELDS, field=const.DESCRIPTION,
                    name=const.NAME, exp_name=expected_name)))
        self.assertEqual(1, len(capabilities[0]))
        self.assertEqual(expected_description,
                         capabilities[0][const.DESCRIPTION])
