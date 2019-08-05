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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class AmphoraAPITest(test_base.LoadBalancerBaseTest):
    """Test the amphora object API."""

    @classmethod
    def skip_checks(cls):
        super(AmphoraAPITest, cls).skip_checks()
        if CONF.load_balancer.provider not in ['amphora', 'octavia']:
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
            cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

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

        # Test that a user without the load balancer admin role cannot
        # create a flavor
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.amphora_client.update_amphora_config,
                amphora_1[const.ID])

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

        # Test RBAC not authorized for non-admin role
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            self.assertRaises(exceptions.Forbidden,
                              self.os_primary.amphora_client.amphora_failover,
                              amphora_1[const.ID])
            self.assertRaises(
                exceptions.Forbidden,
                self.os_roles_lb_member.amphora_client.amphora_failover,
                amphora_1[const.ID])

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
