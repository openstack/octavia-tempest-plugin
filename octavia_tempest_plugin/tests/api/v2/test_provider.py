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

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ProviderAPITest(test_base.LoadBalancerBaseTest):
    """Test the provider object API."""

    @decorators.idempotent_id('8b94e0cc-a24d-4c29-bc8e-53f58214dc67')
    def test_provider_list(self):
        """Tests provider list API and field filtering.

        * Validates that non-lb member accounts cannot list the providers.
        * List the providers and validate against the expected provider list.
        * List the providers returning one field at a time.
        """
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.mem_provider_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('Providers are only available on '
                                     'Octavia API version 2.1 or newer.')

        # Test that a user without the load balancer role cannot
        # list providers.
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
                'os_system_admin', 'os_system_reader', 'os_roles_lb_observer',
                'os_roles_lb_global_observer', 'os_roles_lb_admin',
                'os_roles_lb_member', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'ProviderClient', 'list_providers', expected_allowed)

        providers = self.mem_provider_client.list_providers()

        # Check against the expected providers from the tempest config
        enabled_providers = CONF.load_balancer.enabled_provider_drivers
        for provider in providers:
            self.assertEqual(enabled_providers[provider[const.NAME]],
                             provider.get(const.DESCRIPTION, ''))

        # Test fields
        providers = self.mem_provider_client.list_providers(
            query_params='{fields}={field}'.format(fields=const.FIELDS,
                                                   field=const.NAME))
        for provider in providers:
            self.assertEqual(1, len(provider))
            self.assertIn(provider[const.NAME], enabled_providers.keys())
        providers = self.mem_provider_client.list_providers(
            query_params='{fields}={field}'.format(fields=const.FIELDS,
                                                   field=const.DESCRIPTION))
        for provider in providers:
            self.assertEqual(1, len(provider))
            self.assertIn(provider[const.DESCRIPTION],
                          enabled_providers.values())
