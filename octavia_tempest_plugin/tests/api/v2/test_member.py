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
import time
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


class MemberAPITest(test_base.LoadBalancerBaseTest):
    """Test the member object API."""

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(MemberAPITest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_member")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}
        cls._setup_lb_network_kwargs(lb_kwargs)
        cls.protocol = const.HTTP
        lb_feature_enabled = CONF.loadbalancer_feature_enabled
        if not lb_feature_enabled.l7_protocol_enabled:
            cls.protocol = lb_feature_enabled.l4_protocol

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

        listener_name = data_utils.rand_name("lb_member_listener1_member")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: cls.protocol,
            const.PROTOCOL_PORT: '80',
            const.LOADBALANCER_ID: cls.lb_id,
        }
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)
        cls.listener_id = listener[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_listener_client.cleanup_listener,
            cls.listener_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_member")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: cls.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LISTENER_ID: cls.listener_id,
        }

        pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        cls.pool_id = pool[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_pool_client.cleanup_pool,
            cls.pool_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    def _create_member_and_get_monitor_status(self, **member_kwargs):
        monitor = CONF.loadbalancer_feature_enabled.health_monitor_enabled
        if not monitor:
            del member_kwargs[const.MONITOR_ADDRESS]
            del member_kwargs[const.MONITOR_PORT]
        member = self.mem_member_client.create_member(**member_kwargs)
        return member, monitor

    # Note: This test also covers basic member show API
    @decorators.idempotent_id('0623aa1f-753d-44e7-afa1-017d274eace7')
    def test_member_ipv4_create(self):
        self._test_member_create(4)

    # Note: This test also covers basic member show API
    @decorators.idempotent_id('141944cc-5e2c-4e83-88f8-f61a6797c9b7')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_member_ipv6_create(self):
        self._test_member_create(6)

    def _test_member_create(self, ip_version):
        """Tests member create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create members.
        * Create a fully populated member.
        * If driver doesnt support Monitors, allow to create without monitor
        * Show member details.
        * Validate the show reflects the requested values.
        """
        if ip_version == 4:
            member_address = '192.0.2.1'
            member_monitor_address = '192.0.2.2'
        else:
            member_address = '2001:db8:0:0:0:0:0:1'
            member_monitor_address = '2001:db8:0:0:0:0:0:2'

        member_name = data_utils.rand_name("lb_member_member1-create")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: self.pool_id,
            const.ADDRESS: member_address,
            const.PROTOCOL_PORT: 80,
            const.WEIGHT: 50,
            const.MONITOR_ADDRESS: member_monitor_address,
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

        # Test that a user without the load balancer role cannot
        # create a member
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.member_client.create_member,
                **member_kwargs)

        member, monitor = self._create_member_and_get_monitor_status(
            **member_kwargs)

        self.addClassResourceCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=self.pool_id,
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
            pool_id=self.pool_id)

        parser.parse(member[const.CREATED_AT])
        parser.parse(member[const.UPDATED_AT])
        UUID(member[const.ID])
        self.assertEqual(const.NO_MONITOR, member[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]
        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

    @decorators.idempotent_id('9ce7ad78-915b-42ce-b0d8-44d88a929f3d')
    def test_member_list(self):
        """Tests member list API and field filtering.

        * Create a clean pool.
        * Create three members.
        * Validates that other accounts cannot list the members.
        * List the members using the default sort order.
        * List the members using descending sort order.
        * List the members using ascending sort order.
        * List the members returning one field at a time.
        * List the members returning two fields.
        * List the members filtering to one of the three.
        * List the members filtered, one field, and sorted.
        """
        pool_name = data_utils.rand_name("lb_member_pool2_member-list")
        pool = self.mem_pool_client.create_pool(
            name=pool_name, loadbalancer_id=self.lb_id,
            protocol=self.protocol,
            lb_algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        pool_id = pool[const.ID]
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member1_name = data_utils.rand_name("lb_member_member2-list")
        member1_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 101,
        }
        member1 = self.mem_member_client.create_member(
            **member1_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member1[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        member1 = waiters.wait_for_status(
            self.mem_member_client.show_member, member1[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        member2_name = data_utils.rand_name("lb_member_member1-list")
        member2_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 100,
        }
        member2 = self.mem_member_client.create_member(
            **member2_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        member2 = waiters.wait_for_status(
            self.mem_member_client.show_member, member2[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        member3_name = data_utils.rand_name("lb_member_member3-list")
        member3_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member3_name,
            const.ADMIN_STATE_UP: False,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 102,
        }
        member3 = self.mem_member_client.create_member(
            **member3_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member3[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        member3 = waiters.wait_for_status(
            self.mem_member_client.show_member, member3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)

        # Test that a different user cannot list members
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.member_client
            self.assertRaises(
                exceptions.Forbidden,
                member2_client.list_members,
                pool_id)

        # Test that a user without the lb member role cannot list load
        # balancers
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.member_client.list_members,
                pool_id)

        # Check the default sort order, created_at
        members = self.mem_member_client.list_members(pool_id)
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member3[const.PROTOCOL_PORT],
                         members[2][const.PROTOCOL_PORT])

        # Test sort descending by protocol_port
        members = self.mem_member_client.list_members(
            pool_id, query_params='{sort}={descr}:{desc}'.format(
                sort=const.SORT, descr=const.PROTOCOL_PORT, desc=const.DESC))
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[2][const.PROTOCOL_PORT])
        self.assertEqual(member3[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])

        # Test sort ascending by protocol_port
        members = self.mem_member_client.list_members(
            pool_id, query_params='{sort}={descr}:{asc}'.format(
                sort=const.SORT, descr=const.PROTOCOL_PORT, asc=const.ASC))
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])
        self.assertEqual(member3[const.PROTOCOL_PORT],
                         members[2][const.PROTOCOL_PORT])

        # Test fields
        show_member_response_fields = const.SHOW_MEMBER_RESPONSE_FIELDS
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            show_member_response_fields.append('backup')
        for field in show_member_response_fields:
            members = self.mem_member_client.list_members(
                pool_id, query_params='{fields}={field}'.format(
                    fields=const.FIELDS, field=field))
            self.assertEqual(1, len(members[0]))
            self.assertEqual(member1[field], members[0][field])
            self.assertEqual(member2[field], members[1][field])
            self.assertEqual(member3[field], members[2][field])

        # Test multiple fields at the same time
        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{fields}={admin}&{fields}={created}'.format(
                fields=const.FIELDS, admin=const.ADMIN_STATE_UP,
                created=const.CREATED_AT))
        self.assertEqual(2, len(members[0]))
        self.assertTrue(members[0][const.ADMIN_STATE_UP])
        parser.parse(members[0][const.CREATED_AT])
        self.assertTrue(members[1][const.ADMIN_STATE_UP])
        parser.parse(members[1][const.CREATED_AT])
        self.assertFalse(members[2][const.ADMIN_STATE_UP])
        parser.parse(members[2][const.CREATED_AT])

        # Test filtering
        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{desc}={lb_desc}'.format(
                desc=const.PROTOCOL_PORT,
                lb_desc=member2[const.PROTOCOL_PORT]))
        self.assertEqual(1, len(members))
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])

        # Test combined params
        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{admin}={true}&'
                         '{fields}={descr}&{fields}={id}&'
                         '{sort}={descr}:{desc}'.format(
                             admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, descr=const.PROTOCOL_PORT,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        # Should get two members
        self.assertEqual(2, len(members))
        # members should have two fields
        self.assertEqual(2, len(members[0]))
        # Should be in descending order
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])

    @decorators.idempotent_id('7674ae04-7e92-44ef-9adf-40718d7ec705')
    def test_member_show(self):
        """Tests member show API.

        * Create a fully populated member.
        * Show member details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the member.
        """
        member_name = data_utils.rand_name("lb_member_member1-show")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: self.pool_id,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 81,
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

        member, monitor = self._create_member_and_get_monitor_status(
            **member_kwargs)

        self.addClassResourceCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=self.pool_id,
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
            pool_id=self.pool_id)

        parser.parse(member[const.CREATED_AT])
        parser.parse(member[const.UPDATED_AT])
        UUID(member[const.ID])
        self.assertEqual(const.NO_MONITOR, member[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]
        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

        # Test that a user with lb_admin role can see the member
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            member_client = self.os_roles_lb_admin.member_client
            member_adm = member_client.show_member(
                member[const.ID], pool_id=self.pool_id)
            self.assertEqual(member_name, member_adm[const.NAME])

        # Test that a user with cloud admin role can see the member
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            adm = self.os_admin.member_client.show_member(
                member[const.ID], pool_id=self.pool_id)
            self.assertEqual(member_name, adm[const.NAME])

        # Test that a different user, with load balancer member role, cannot
        # see this member
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.member_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.show_member,
                              member[const.ID], pool_id=self.pool_id)

        # Test that a user, without the load balancer member role, cannot
        # show members
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.member_client.show_member,
                member[const.ID], pool_id=self.pool_id)

    @decorators.idempotent_id('c07572b8-e853-48f3-a8ea-37fc293a4724')
    def test_member_update(self):
        """Tests member show API and field filtering.

        * Create a fully populated member.
        * Show member details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the member.
        * Update the member details.
        * Show member details.
        * Validate the show reflects the initial values.
        """
        member_name = data_utils.rand_name("lb_member_member1-update")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: False,
            const.POOL_ID: self.pool_id,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 82,
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

        member, monitor = self._create_member_and_get_monitor_status(
            **member_kwargs)

        self.addClassResourceCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=self.pool_id,
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
            pool_id=self.pool_id)
        status = const.OFFLINE
        if not monitor or CONF.load_balancer.test_with_noop:
            status = const.NO_MONITOR
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.OPERATING_STATUS,
            status,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=self.pool_id)

        parser.parse(member[const.CREATED_AT])
        parser.parse(member[const.UPDATED_AT])
        UUID(member[const.ID])

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]
        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

        if CONF.load_balancer.test_with_noop or not monitor:
            # Operating status with noop or Driver not supporting Monitors
            # will stay in NO_MONITOR
            self.assertEqual(const.NO_MONITOR, member[const.OPERATING_STATUS])
        else:
            # Operating status will be OFFLINE while admin_state_up = False
            self.assertEqual(const.OFFLINE, member[const.OPERATING_STATUS])

        # Test that a user, without the load balancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.member_client.update_member,
                member[const.ID], pool_id=self.pool_id, admin_state_up=True)

        # Assert we didn't go into PENDING_*
        member_check = self.mem_member_client.show_member(
            member[const.ID], pool_id=self.pool_id)
        self.assertEqual(const.ACTIVE,
                         member_check[const.PROVISIONING_STATUS])
        self.assertEqual(member_kwargs[const.ADMIN_STATE_UP],
                         member_check[const.ADMIN_STATE_UP])

        # Test that a user, without the load balancer member role, cannot
        # update this member
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.member_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.update_member,
                              member[const.ID], pool_id=self.pool_id,
                              admin_state_up=True)

        # Assert we didn't go into PENDING_*
        member_check = self.mem_member_client.show_member(
            member[const.ID], pool_id=self.pool_id)
        self.assertEqual(const.ACTIVE,
                         member_check[const.PROVISIONING_STATUS])
        self.assertEqual(member_kwargs[const.ADMIN_STATE_UP],
                         member_check[const.ADMIN_STATE_UP])

        new_name = data_utils.rand_name("lb_member_member1-UPDATED")
        member_update_kwargs = {
            const.POOL_ID: member_kwargs[const.POOL_ID],
            const.NAME: new_name,
            const.ADMIN_STATE_UP: not member[const.ADMIN_STATE_UP],
            const.WEIGHT: member[const.WEIGHT] + 1,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_update_kwargs.update({
                const.BACKUP: not member[const.BACKUP]
            })
        if monitor:
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
            pool_id=self.pool_id)
        if not CONF.load_balancer.test_with_noop:
            member = waiters.wait_for_status(
                self.mem_member_client.show_member,
                member[const.ID], const.OPERATING_STATUS,
                const.NO_MONITOR,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout,
                pool_id=self.pool_id)

        # Operating status will be NO_MONITOR regardless of noop
        self.assertEqual(const.NO_MONITOR, member[const.OPERATING_STATUS])

        # Test changed items
        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.WEIGHT]

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]
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

    @decorators.idempotent_id('83e0a9f2-491f-46a8-b3ce-6969d70a4e9f')
    def test_member_batch_update(self):
        """Tests member batch update.

        * Create two members.
        * Batch update the members so one is deleted, created, and updated
        * Validate the member list is correct.
        """
        pool_name = data_utils.rand_name("lb_member_pool3_member-batch")
        pool = self.mem_pool_client.create_pool(
            name=pool_name, loadbalancer_id=self.lb_id,
            protocol=self.protocol,
            lb_algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        pool_id = pool[const.ID]
        self.addClassResourceCleanup(
            self.mem_pool_client.cleanup_pool, pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member1_name = data_utils.rand_name("lb_member_member1-batch")
        member1_kwargs = {
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: pool_id,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 80,
            const.WEIGHT: 50,
            const.MONITOR_ADDRESS: '192.0.2.2',
            const.MONITOR_PORT: 8080,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member1_kwargs.update({
                const.BACKUP: False,
            })

        if self.lb_member_vip_subnet:
            member1_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]
        member1, monitor = self._create_member_and_get_monitor_status(
            **member1_kwargs)

        self.addClassResourceCleanup(
            self.mem_member_client.cleanup_member,
            member1[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member2_name = data_utils.rand_name("lb_member_member2-batch")
        member2_kwargs = {
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: pool_id,
            const.ADDRESS: '192.0.2.3',
            const.PROTOCOL_PORT: 81,
            const.WEIGHT: 51,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member2_kwargs.update({
                const.BACKUP: True,
            })

        if monitor:
            member2_kwargs[const.MONITOR_ADDRESS] = '192.0.2.4'
            member2_kwargs[const.MONITOR_PORT] = 8081
        if self.lb_member_vip_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        member2 = self.mem_member_client.create_member(**member2_kwargs)
        self.addClassResourceCleanup(
            self.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member3_name = data_utils.rand_name("lb_member_member3-batch")
        member3_kwargs = {
            const.NAME: member3_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: '192.0.2.5',
            const.PROTOCOL_PORT: 82,
            const.WEIGHT: 52,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member3_kwargs.update({
                const.BACKUP: True,
            })

        if monitor:
            member2_kwargs[const.MONITOR_ADDRESS] = '192.0.2.6'
            member2_kwargs[const.MONITOR_PORT] = 8082
        if self.lb_member_vip_subnet:
            member3_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        member2_name_update = data_utils.rand_name("lb_member_member2-new")
        member2_kwargs[const.NAME] = member2_name_update
        member2_kwargs.pop(const.POOL_ID)
        batch_update_list = [member2_kwargs, member3_kwargs]

        # Test that a user, without the load balancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.member_client.update_members,
                pool_id=self.pool_id, members_list=batch_update_list)

        # Assert we didn't go into PENDING_*
        member_check = self.mem_member_client.show_member(
            member2[const.ID], pool_id=pool_id)
        self.assertEqual(const.ACTIVE, member_check[const.PROVISIONING_STATUS])
        self.assertEqual(member2_name, member_check[const.NAME])

        self.mem_member_client.update_members(
            pool_id=pool_id, members_list=batch_update_list)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{sort}={port}:{asc}'.format(
                sort=const.SORT, port=const.PROTOCOL_PORT, asc=const.ASC))
        for m in members:
            self.addClassResourceCleanup(
                self.mem_member_client.cleanup_member,
                m[const.ID], pool_id=pool_id,
                lb_client=self.mem_lb_client, lb_id=self.lb_id)

        # We should have two members: member2 and member3, in that order
        self.assertEqual(2, len(members))
        # Member2 is the same ID
        self.assertEqual(member2[const.ID], members[0][const.ID])
        # Member3 will have a different ID (not member1)
        self.assertNotEqual(member1[const.ID], members[1][const.ID])

        # Member2's name should be updated, and member3 should exist
        self.assertEqual(member2_name_update, members[0][const.NAME])
        self.assertEqual(member3_name, members[1][const.NAME])

    @decorators.idempotent_id('f129ba5e-a16e-4178-924f-6a9c5b8b1589')
    def test_member_delete(self):
        """Tests member create and delete APIs.

        * Creates a member.
        * Validates that other accounts cannot delete the member
        * Deletes the member.
        * Validates the member is in the DELETED state.
        """
        member_name = data_utils.rand_name("lb_member_member1-delete")
        member_kwargs = {
            const.POOL_ID: self.pool_id,
            const.NAME: member_name,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 83,
        }
        member = self.mem_member_client.create_member(**member_kwargs)
        self.addClassResourceCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=self.pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the load balancer role cannot
        # delete this member
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.member_client.delete_member,
                member[const.ID], pool_id=self.pool_id)

        # Test that a different user, with the load balancer member role
        # cannot delete this member
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.member_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.delete_member,
                              member[const.ID], pool_id=self.pool_id)

        self.mem_member_client.delete_member(member[const.ID],
                                             pool_id=self.pool_id)

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_member_client.show_member, member[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout,
            pool_id=self.pool_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
