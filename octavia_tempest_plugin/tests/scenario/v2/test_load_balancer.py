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

import testtools
from uuid import UUID

from dateutil import parser

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class LoadBalancerScenarioTest(test_base.LoadBalancerBaseTest):

    @decorators.idempotent_id('a5e2e120-4f7e-4c8b-8aac-cf09cb56711c')
    def test_load_balancer_ipv4_CRUD(self):
        self._test_load_balancer_CRUD(4)

    @decorators.idempotent_id('86ffecc4-dce8-46f9-936e-8a4c6bcf3959')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_load_balancer_ipv6_CRUD(self):
        self._test_load_balancer_CRUD(6)

    def _test_load_balancer_CRUD(self, ip_version):
        """Tests load balancer create, read, update, delete

        * Create a fully populated load balancer.
        * Show load balancer details.
        * Update the load balancer.
        * Delete the load balancer.
        """
        lb_name = data_utils.rand_name("lb_member_lb1-CRUD")
        lb_description = data_utils.arbitrary_string(size=255)

        lb_kwargs = {const.ADMIN_STATE_UP: False,
                     const.DESCRIPTION: lb_description,
                     const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        self._setup_lb_network_kwargs(lb_kwargs, ip_version)

        lb = self.mem_lb_client.create_loadbalancer(**lb_kwargs)
        self.addCleanup(
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
        if ip_version == 4:
            self.assertEqual(self.lb_member_vip_net[const.ID],
                             lb[const.VIP_NETWORK_ID])
        else:
            self.assertEqual(self.lb_member_vip_ipv6_net[const.ID],
                             lb[const.VIP_NETWORK_ID])
        self.assertIsNotNone(lb[const.VIP_PORT_ID])
        if lb_kwargs[const.VIP_SUBNET_ID]:
            self.assertEqual(lb_kwargs[const.VIP_SUBNET_ID],
                             lb[const.VIP_SUBNET_ID])

        # Load balancer update
        new_name = data_utils.rand_name("lb_member_lb1-update")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        lb = self.mem_lb_client.update_loadbalancer(
            lb[const.ID],
            admin_state_up=True,
            description=new_description,
            name=new_name)

        lb = waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                     lb[const.ID], const.PROVISIONING_STATUS,
                                     const.ACTIVE,
                                     CONF.load_balancer.lb_build_interval,
                                     CONF.load_balancer.lb_build_timeout)

        self.assertTrue(lb[const.ADMIN_STATE_UP])
        self.assertEqual(new_description, lb[const.DESCRIPTION])
        self.assertEqual(new_name, lb[const.NAME])

        # Load balancer delete
        self.mem_lb_client.delete_loadbalancer(lb[const.ID], cascade=True)

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_lb_client.show_loadbalancer, lb[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
