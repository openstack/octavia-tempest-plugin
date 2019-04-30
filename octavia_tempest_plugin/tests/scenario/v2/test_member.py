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


class MemberScenarioTest(test_base.LoadBalancerBaseTest):

    member_address = '2001:db8:0:0:0:0:0:1'

    @classmethod
    def resource_setup(cls):
        """Setup shared resources needed by the tests."""
        super(MemberScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_member")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        cls._setup_lb_network_kwargs(lb_kwargs,
                                     ip_version=4)

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

        # Per protocol listeners and pools IDs
        cls.listener_ids = {}
        cls.pool_ids = {}

        cls.protocol = const.HTTP
        lb_feature_enabled = CONF.loadbalancer_feature_enabled
        if not lb_feature_enabled.l7_protocol_enabled:
            cls.protocol = lb_feature_enabled.l4_protocol

        # Don't use same ports for HTTP/l4_protocol and UDP since some previous
        # releases (<=train) don't support it
        cls._listener_pool_create(cls.protocol, 80)

        cls._listener_pool_create(const.UDP, 8080)

    @classmethod
    def _listener_pool_create(cls, protocol, protocol_port):
        """Setup resources needed by the tests."""

        if (protocol == const.UDP and
                not cls.mem_listener_client.is_version_supported(
                    cls.api_version, '2.1')):
            return

        listener_name = data_utils.rand_name("lb_member_listener1_member")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: cls.lb_id,
            # For branches that don't support multiple listeners in single
            # haproxy process and use haproxy>=1.8:
            const.CONNECTION_LIMIT: 200,
        }
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)
        cls.listener_ids[protocol] = listener[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_listener_client.cleanup_listener,
            cls.listener_ids[protocol],
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_member")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: cls.lb_algorithm,
            const.LISTENER_ID: cls.listener_ids[protocol],
        }
        pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        cls.pool_ids[protocol] = pool[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_pool_client.cleanup_pool,
            cls.pool_ids[protocol],
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    @decorators.idempotent_id('15c8c3e3-569c-4029-95df-a9f72049e267')
    def test_member_CRUD(self):
        """Tests member create, read, update, delete

        * Create a fully populated member.
        * Show member details.
        * Update the member.
        * Delete the member.
        """

        # Member create
        member_name = data_utils.rand_name("lb_member_member1-CRUD")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: self.pool_ids[self.protocol],
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 80,
            const.WEIGHT: 50,
            const.MONITOR_ADDRESS: '192.0.2.2',
            const.MONITOR_PORT: 8080,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_kwargs.update({
                const.BACKUP: False,
            })

        if self.lb_member_vip_subnet:
            member_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]
        hm_enabled = CONF.loadbalancer_feature_enabled.health_monitor_enabled
        if not hm_enabled:
            del member_kwargs[const.MONITOR_ADDRESS]
            del member_kwargs[const.MONITOR_PORT]
        member = self.mem_member_client.create_member(**member_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=self.pool_ids[self.protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[self.protocol])

        parser.parse(member[const.CREATED_AT])
        parser.parse(member[const.UPDATED_AT])
        UUID(member[const.ID])

        # Members may be in a transitional state initially
        # like DOWN or MAINT, give it some time to stablize on
        # NO_MONITOR. This is LIVE status.
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout,
            pool_id=self.pool_ids[self.protocol])

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]
        if hm_enabled:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

        # Member update
        new_name = data_utils.rand_name("lb_member_member1-update")
        member_update_kwargs = {
            const.POOL_ID: member_kwargs[const.POOL_ID],
            const.NAME: new_name,
            const.ADMIN_STATE_UP: not member[const.ADMIN_STATE_UP],
            const.WEIGHT: member[const.WEIGHT] + 1,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_update_kwargs.update({
                const.BACKUP: not member[const.BACKUP],
            })

        if hm_enabled:
            member_update_kwargs[const.MONITOR_ADDRESS] = '192.0.2.3'
            member_update_kwargs[const.MONITOR_PORT] = member[
                const.MONITOR_PORT] + 1
        member = self.mem_member_client.update_member(
            member[const.ID], **member_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_ids[self.protocol])

        # Test changed items
        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.WEIGHT]
        if hm_enabled:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        for item in equal_items:
            self.assertEqual(member_update_kwargs[item], member[item])

        # Test unchanged items
        equal_items = [const.ADDRESS, const.PROTOCOL_PORT]
        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

        # Member delete
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        self.mem_member_client.delete_member(
            member[const.ID],
            pool_id=self.pool_ids[self.protocol])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_member_client.show_member, member[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout,
            pool_id=self.pool_ids[self.protocol])

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

    def _test_mixed_member_create(self, protocol):
        member_name = data_utils.rand_name("lb_member_member1-create")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: self.pool_ids[protocol],
            const.ADDRESS: self.member_address,
            const.PROTOCOL_PORT: 80,
            const.WEIGHT: 50,
        }

        if self.lb_member_vip_subnet:
            member_kwargs[const.SUBNET_ID] = (
                self.lb_member_vip_subnet[const.ID])

        member = self.mem_member_client.create_member(
            **member_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=self.pool_ids[protocol],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

    @decorators.idempotent_id('0623aa1f-753d-44e7-afa1-017d274eace7')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_mixed_udp_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""

        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')

        self._test_mixed_member_create(const.UDP)

    @decorators.idempotent_id('b8afb91d-9b85-4569-85c7-03453df8990b')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        self._test_mixed_member_create(self.protocol)
