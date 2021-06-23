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

import testtools
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


class AmphoraAPITest(test_base.LoadBalancerBaseTest):
    """Test the amphora object API."""

    @classmethod
    def skip_checks(cls):
        super(AmphoraAPITest, cls).skip_checks()
        if CONF.load_balancer.provider not in const.AMPHORA_PROVIDERS:
            raise cls.skipException('Amphora tests only run with the amphora '
                                    'provider enabled.')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(AmphoraAPITest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1-amphora-api")
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

    def _expected_amp_count(self, amp_list):
        self.assertNotEmpty(amp_list)
        if amp_list[0][const.ROLE] in (const.ROLE_MASTER, const.ROLE_BACKUP):
            return 2
        return 1

    @decorators.idempotent_id('a0e9ff99-2c4f-45d5-81c9-78d3107c236f')
    def test_amphora_list_and_show(self):
        """Tests amphora show API.

        * Show amphora details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the amphora.
        """
        lb_name = data_utils.rand_name("lb_member_lb2_amphora-list")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
            vip_network_id=self.lb_member_vip_net[const.ID])
        lb_id = lb[const.ID]
        self.addCleanup(self.mem_lb_client.cleanup_loadbalancer, lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        # Test RBAC for list amphorae
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'AmphoraClient', 'list_amphorae', expected_allowed)

        # Get an actual list of the amphorae
        amphorae = self.lb_admin_amphora_client.list_amphorae()

        # There should be AT LEAST 2, there may be more depending on the
        # configured topology
        self.assertGreaterEqual(
            len(amphorae), 2 * self._expected_amp_count(amphorae))

        # Test filtering by loadbalancer_id
        amphorae = self.lb_admin_amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))
        self.assertEqual(self._expected_amp_count(amphorae), len(amphorae))
        self.assertEqual(self.lb_id, amphorae[0][const.LOADBALANCER_ID])

        # Test RBAC for show amphora
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'AmphoraClient', 'show_amphora', expected_allowed,
                amphora_id=amphorae[0][const.ID])

        show_amphora_response_fields = const.SHOW_AMPHORA_RESPONSE_FIELDS
        if self.lb_admin_amphora_client.is_version_supported(
                self.api_version, '2.1'):
            show_amphora_response_fields.append('created_at')
            show_amphora_response_fields.append('updated_at')
            show_amphora_response_fields.append('image_id')

        for amp in amphorae:

            # Make sure all of the fields exist on the amp list records
            for field in show_amphora_response_fields:
                self.assertIn(field, amp)

            # Verify a few of the fields are the right type
            if self.lb_admin_amphora_client.is_version_supported(
                    self.api_version, '2.1'):
                parser.parse(amp[const.CREATED_AT])
                parser.parse(amp[const.UPDATED_AT])

            UUID(amp[const.ID])
            UUID(amp[const.HA_PORT_ID])
            UUID(amp[const.LOADBALANCER_ID])
            UUID(amp[const.COMPUTE_ID])
            UUID(amp[const.VRRP_PORT_ID])
            self.assertEqual(amp[const.STATUS], const.STATUS_ALLOCATED)
            self.assertIn(amp[const.ROLE], const.AMPHORA_ROLES)

            # Test that all of the fields from the amp list match those
            # from a show for the LB we created.
            amp_obj = self.lb_admin_amphora_client.show_amphora(
                amphora_id=amp[const.ID])
            for field in show_amphora_response_fields:
                self.assertEqual(amp[field], amp_obj[field])

    @decorators.idempotent_id('b7fc231b-dcfa-47a5-99f3-ec5ddcc48f30')
    def test_amphora_update(self):
        """Tests the amphora agent configuration update API

        * Tests that users without the loadbalancer admin role cannot
          update an amphora.
        * Update the amphora.
        """

        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.lb_admin_amphora_client.is_version_supported(
                self.api_version, '2.7'):
            raise self.skipException('Amphora update is only available on '
                                     'Octavia API version 2.7 or newer.')

        amphorae = self.lb_admin_amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))
        amphora_1 = amphorae[0]

        # Test RBAC for update an amphora
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'AmphoraClient', 'update_amphora_config', expected_allowed,
                None, None, amphora_1[const.ID])

        self.lb_admin_amphora_client.update_amphora_config(amphora_1[const.ID])

        # TODO(johnsom) Assert that an amphora config setting updated
        #               when we have a setting to check.

        amp = self.lb_admin_amphora_client.show_amphora(amphora_1[const.ID])

        self.assertEqual(const.STATUS_ALLOCATED, amp[const.STATUS])

    @decorators.idempotent_id('fb772680-b2ba-4fc3-989b-95ad8492ccaf')
    def test_amphora_failover(self):
        """Tests the amphora failover API.

        * Validates that non-admin accounts cannot failover amphora
        * Fails over an amphora
        * Validates that a new amphora is built
        """
        amphorae = self.lb_admin_amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))
        amphora_1 = amphorae[0]

        # Test RBAC for failover an amphora
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'AmphoraClient', 'amphora_failover', expected_allowed,
                None, None, amphora_1[const.ID])

        self.lb_admin_amphora_client.amphora_failover(amphora_1[const.ID])

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        after_amphorae = self.lb_admin_amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))

        for new_amp in after_amphorae:
            self.assertNotEqual(amphora_1[const.ID], new_amp[const.ID])

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Log offload tests will not work in noop mode.')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.log_offload_enabled,
        'Skipping log offload tests because tempest configuration '
        '[loadbalancer-feature-enabled] log_offload_enabled is False.')
    @decorators.idempotent_id('4e3c6fcb-5f83-4da1-8296-56f209eae30d')
    def test_admin_log(self):
        """Tests admin log offloading

        * Create a listener
        * Validates the listener config log message is present
        """
        listener_name = data_utils.rand_name("lb_member_listener1_admin_log")
        protocol_port = '8124'
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: protocol_port,
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

        # We need to give the log subsystem time to commit the log
        time.sleep(CONF.load_balancer.check_interval)

        # Check for an amphora agent API call and code log entry
        # One is logged via the gunicorn logging and the other via
        # oslo.logging.
        agent_found = False
        client_found = False
        with open(CONF.load_balancer.amphora_admin_log_file) as f:
            for line in f:
                if 'Octavia HaProxy Rest Client' in line:
                    client_found = True
                if ' amphora-agent: ' in line:
                    agent_found = True
                if client_found and agent_found:
                    break

        self.assertTrue(
            client_found,
            'Octavia user agent string was not found in: {0}'.format(
                CONF.load_balancer.amphora_admin_log_file))

        self.assertTrue(
            agent_found, 'Amphora agent string was not found in: {0}'.format(
                CONF.load_balancer.amphora_admin_log_file))
