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


class AmphoraScenarioTest(test_base.LoadBalancerBaseTest):
    """Test the amphora object API."""

    @classmethod
    def skip_checks(cls):
        super(AmphoraScenarioTest, cls).skip_checks()

        if CONF.load_balancer.provider not in ['amphora', 'octavia']:
            raise cls.skipException("Amphora tests require provider 'amphora' "
                                    "or 'octavia' (alias to 'amphora', "
                                    " deprecated) set")

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(AmphoraScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_amphora")
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
            name=lb_name,
            vip_network_id=self.lb_member_vip_net[const.ID])
        lb_id = lb[const.ID]
        self.addCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        # Test that a user with lb_admin role can list the amphora
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            amphora_client = self.os_roles_lb_admin.amphora_client
            amphora_adm = amphora_client.list_amphorae()
            self.assertTrue(
                len(amphora_adm) >= 2 * self._expected_amp_count(amphora_adm))

        # Test that a different user, with load balancer member role, cannot
        # see this amphora
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.amphora_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.list_amphorae)

        # Test that a user, without the load balancer member role, cannot
        # list amphorae
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.amphora_client.list_amphorae)

        # Test that a user with cloud admin role can list the amphorae
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            adm = self.os_admin.amphora_client.list_amphorae()
            self.assertTrue(len(adm) >= 2 * self._expected_amp_count(adm))

        # Get an actual list of the amphorae
        amphorae = self.os_admin.amphora_client.list_amphorae()

        # There should be AT LEAST 2, there may be more depending on the
        # configured topology, or if there are other LBs created besides ours
        self.assertTrue(
            len(amphorae) >= 2 * self._expected_amp_count(amphorae))

        show_amphora_response_fields = const.SHOW_AMPHORA_RESPONSE_FIELDS
        if self.mem_amphora_client.is_version_supported(
                self.api_version, '2.1'):
            show_amphora_response_fields.append('created_at')
            show_amphora_response_fields.append('updated_at')
            show_amphora_response_fields.append('image_id')

        for amp in amphorae:

            # Make sure all of the fields exist on the amp list records
            for field in show_amphora_response_fields:
                self.assertIn(field, amp)

            amp_id = amp[const.ID]
            amp_obj = self.os_admin.amphora_client.show_amphora(
                amphora_id=amp_id)

            # Make sure all of the fields exist on the amp show record
            for field in show_amphora_response_fields:
                self.assertIn(field, amp_obj)

            # Verify a few of the fields are the right type
            if self.mem_amphora_client.is_version_supported(
                    self.api_version, '2.1'):
                parser.parse(amp_obj[const.CREATED_AT])
                parser.parse(amp_obj[const.UPDATED_AT])
            UUID(amp_obj[const.ID])
            self.assertIn(amp_obj[const.STATUS], const.AMPHORA_STATUSES)

            # We might have gotten unassigned/spare amps?
            if amp_obj[const.STATUS] == const.STATUS_ALLOCATED:
                # Only check the state of fields for the LB we created,
                # otherwise some fields (HA_PORT_ID) may not yet be
                # populated in amps for parallel tests.
                if lb_id == amp_obj[const.LOADBALANCER_ID]:
                    UUID(amp_obj[const.HA_PORT_ID])
                    UUID(amp_obj[const.LOADBALANCER_ID])
                    UUID(amp_obj[const.COMPUTE_ID])
                    UUID(amp_obj[const.VRRP_PORT_ID])
                    self.assertIn(amp_obj[const.ROLE], const.AMPHORA_ROLES)
            else:
                self.assertIsNone(amp_obj[const.ROLE])

            # Test that all of the fields from the amp list match those
            # from a show
            for field in show_amphora_response_fields:
                self.assertEqual(amp[field], amp_obj[field])

        # Test filtering by loadbalancer_id
        amphorae = self.os_admin.amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))
        self.assertEqual(self._expected_amp_count(amphorae), len(amphorae))
        self.assertEqual(self.lb_id, amphorae[0][const.LOADBALANCER_ID])

        amphorae = self.os_admin.amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=lb_id))
        self.assertEqual(self._expected_amp_count(amphorae), len(amphorae))
        self.assertEqual(lb_id, amphorae[0][const.LOADBALANCER_ID])
