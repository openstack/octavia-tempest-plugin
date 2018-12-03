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


class PoolAPITest(test_base.LoadBalancerBaseTest):
    """Test the pool object API."""

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(PoolAPITest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_pool")
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

        listener_name = data_utils.rand_name("lb_member_listener1_pool")
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

    @decorators.idempotent_id('7587fe48-87ba-4538-9f03-190911f100ff')
    def test_pool_create_standalone(self):
        self._test_pool_create(has_listener=False)

    @decorators.idempotent_id('c9c0df79-f07e-428c-ae57-b9d4078eec79')
    def test_pool_create_with_listener(self):
        self._test_pool_create(has_listener=True)

    def _test_pool_create(self, has_listener):
        """Tests pool create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create pools.
        * Create a fully populated pool.
        * Show pool details.
        * Validate the show reflects the requested values.
        """
        pool_name = data_utils.rand_name("lb_member_pool1-create")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name,
            },
        }
        if has_listener:
            pool_kwargs[const.LISTENER_ID] = self.listener_id
        else:
            pool_kwargs[const.LOADBALANCER_ID] = self.lb_id

        # Test that a user without the load balancer role cannot
        # create a pool
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.pool_client.create_pool,
                **pool_kwargs)

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addClassResourceCleanup(
            self.mem_pool_client.cleanup_pool,
            pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        pool = waiters.wait_for_status(
            self.mem_pool_client.show_pool,
            pool[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if has_listener and not CONF.load_balancer.test_with_noop:
            pool = waiters.wait_for_status(
                self.mem_pool_client.show_pool,
                pool[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(pool_name, pool[const.NAME])
        self.assertEqual(pool_description, pool[const.DESCRIPTION])
        self.assertTrue(pool[const.ADMIN_STATE_UP])
        parser.parse(pool[const.CREATED_AT])
        parser.parse(pool[const.UPDATED_AT])
        UUID(pool[const.ID])
        # Operating status for a pool without members will be:
        if has_listener and not CONF.load_balancer.test_with_noop:
            # ONLINE if it is attached to a listener and is a live test
            self.assertEqual(const.ONLINE, pool[const.OPERATING_STATUS])
        else:
            # OFFLINE if it is just on the LB directly or is in noop mode
            self.assertEqual(const.OFFLINE, pool[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        if has_listener:
            self.assertEqual(1, len(pool[const.LISTENERS]))
            self.assertEqual(self.listener_id,
                             pool[const.LISTENERS][0][const.ID])
        else:
            self.assertEmpty(pool[const.LISTENERS])
        self.assertEqual(const.LB_ALGORITHM_ROUND_ROBIN,
                         pool[const.LB_ALGORITHM])
        self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
        self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                         pool[const.SESSION_PERSISTENCE][const.TYPE])
        self.assertEqual(pool_sp_cookie_name,
                         pool[const.SESSION_PERSISTENCE][const.COOKIE_NAME])

    @decorators.idempotent_id('6959a32e-fb34-4f3e-be68-8880c6450016')
    def test_pool_list(self):
        """Tests pool list API and field filtering.

        * Create a clean loadbalancer.
        * Create three pools.
        * Validates that other accounts cannot list the pools.
        * List the pools using the default sort order.
        * List the pools using descending sort order.
        * List the pools using ascending sort order.
        * List the pools returning one field at a time.
        * List the pools returning two fields.
        * List the pools filtering to one of the three.
        * List the pools filtered, one field, and sorted.
        """
        lb_name = data_utils.rand_name("lb_member_lb2_pool-list")
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

        pool1_name = data_utils.rand_name("lb_member_pool2-list")
        pool1_desc = 'B'
        pool1_sp_cookie_name = 'my_cookie1'
        pool1_kwargs = {
            const.NAME: pool1_name,
            const.DESCRIPTION: pool1_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool1_sp_cookie_name,
            },
            const.LOADBALANCER_ID: lb_id,
        }
        pool1 = self.mem_pool_client.create_pool(
            **pool1_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool,
            pool1[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        pool1 = waiters.wait_for_status(
            self.mem_pool_client.show_pool, pool1[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        pool2_name = data_utils.rand_name("lb_member_pool1-list")
        pool2_desc = 'A'
        pool2_sp_cookie_name = 'my_cookie2'
        pool2_kwargs = {
            const.NAME: pool2_name,
            const.DESCRIPTION: pool2_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool2_sp_cookie_name,
            },
            const.LOADBALANCER_ID: lb_id,
        }
        pool2 = self.mem_pool_client.create_pool(
            **pool2_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool,
            pool2[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        pool2 = waiters.wait_for_status(
            self.mem_pool_client.show_pool, pool2[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        pool3_name = data_utils.rand_name("lb_member_pool3-list")
        pool3_desc = 'C'
        pool3_kwargs = {
            const.NAME: pool3_name,
            const.DESCRIPTION: pool3_desc,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            # No session persistence, just so there's one test for that
            const.LOADBALANCER_ID: lb_id,
        }
        pool3 = self.mem_pool_client.create_pool(
            **pool3_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool,
            pool3[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        pool3 = waiters.wait_for_status(
            self.mem_pool_client.show_pool, pool3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Test that a different user cannot list pools
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.pool_client
            primary = member2_client.list_pools(
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))
            self.assertEqual(0, len(primary))

        # Test that a user without the lb member role cannot list load
        # balancers
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.pool_client.list_pools)

        # Check the default sort order, created_at
        pools = self.mem_pool_client.list_pools(
            query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))
        self.assertEqual(pool1[const.DESCRIPTION],
                         pools[0][const.DESCRIPTION])
        self.assertEqual(pool2[const.DESCRIPTION],
                         pools[1][const.DESCRIPTION])
        self.assertEqual(pool3[const.DESCRIPTION],
                         pools[2][const.DESCRIPTION])

        # Test sort descending by description
        pools = self.mem_pool_client.list_pools(
            query_params='loadbalancer_id={lb_id}&{sort}={descr}:{desc}'
                         .format(lb_id=lb_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, desc=const.DESC))
        self.assertEqual(pool1[const.DESCRIPTION],
                         pools[1][const.DESCRIPTION])
        self.assertEqual(pool2[const.DESCRIPTION],
                         pools[2][const.DESCRIPTION])
        self.assertEqual(pool3[const.DESCRIPTION],
                         pools[0][const.DESCRIPTION])

        # Test sort ascending by description
        pools = self.mem_pool_client.list_pools(
            query_params='loadbalancer_id={lb_id}&{sort}={descr}:{asc}'
                         .format(lb_id=lb_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, asc=const.ASC))
        self.assertEqual(pool1[const.DESCRIPTION],
                         pools[1][const.DESCRIPTION])
        self.assertEqual(pool2[const.DESCRIPTION],
                         pools[0][const.DESCRIPTION])
        self.assertEqual(pool3[const.DESCRIPTION],
                         pools[2][const.DESCRIPTION])

        # Test fields
        for field in const.SHOW_POOL_RESPONSE_FIELDS:
            pools = self.mem_pool_client.list_pools(
                query_params='loadbalancer_id={lb_id}&{fields}={field}'
                             .format(lb_id=lb_id,
                                     fields=const.FIELDS, field=field))
            self.assertEqual(1, len(pools[0]))
            self.assertEqual(pool1[field], pools[0][field])
            self.assertEqual(pool2[field], pools[1][field])
            self.assertEqual(pool3[field], pools[2][field])

        # Test multiple fields at the same time
        pools = self.mem_pool_client.list_pools(
            query_params='loadbalancer_id={lb_id}&{fields}={admin}&'
                         '{fields}={created}'.format(
                             lb_id=lb_id, fields=const.FIELDS,
                             admin=const.ADMIN_STATE_UP,
                             created=const.CREATED_AT))
        self.assertEqual(2, len(pools[0]))
        self.assertTrue(pools[0][const.ADMIN_STATE_UP])
        parser.parse(pools[0][const.CREATED_AT])
        self.assertTrue(pools[1][const.ADMIN_STATE_UP])
        parser.parse(pools[1][const.CREATED_AT])
        self.assertFalse(pools[2][const.ADMIN_STATE_UP])
        parser.parse(pools[2][const.CREATED_AT])

        # Test filtering
        pools = self.mem_pool_client.list_pools(
            query_params='loadbalancer_id={lb_id}&{desc}={lb_desc}'.format(
                lb_id=lb_id, desc=const.DESCRIPTION,
                lb_desc=pool2[const.DESCRIPTION]))
        self.assertEqual(1, len(pools))
        self.assertEqual(pool2[const.DESCRIPTION],
                         pools[0][const.DESCRIPTION])

        # Test combined params
        pools = self.mem_pool_client.list_pools(
            query_params='loadbalancer_id={lb_id}&{admin}={true}&'
                         '{fields}={descr}&{fields}={id}&'
                         '{sort}={descr}:{desc}'.format(
                             lb_id=lb_id, admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, descr=const.DESCRIPTION,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        # Should get two pools
        self.assertEqual(2, len(pools))
        # pools should have two fields
        self.assertEqual(2, len(pools[0]))
        # Should be in descending order
        self.assertEqual(pool2[const.DESCRIPTION],
                         pools[1][const.DESCRIPTION])
        self.assertEqual(pool1[const.DESCRIPTION],
                         pools[0][const.DESCRIPTION])

    @decorators.idempotent_id('b7932438-1aea-4175-a50c-984fee1c0cad')
    def test_pool_show(self):
        """Tests pool show API.

        * Create a fully populated pool.
        * Show pool details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the pool.
        """
        pool_name = data_utils.rand_name("lb_member_pool1-show")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name,
            },
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addClassResourceCleanup(
            self.mem_pool_client.cleanup_pool,
            pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        pool = waiters.wait_for_status(
            self.mem_pool_client.show_pool,
            pool[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(pool_name, pool[const.NAME])
        self.assertEqual(pool_description, pool[const.DESCRIPTION])
        self.assertTrue(pool[const.ADMIN_STATE_UP])
        parser.parse(pool[const.CREATED_AT])
        parser.parse(pool[const.UPDATED_AT])
        UUID(pool[const.ID])
        # Operating status for pools will always be offline without members
        self.assertEqual(const.OFFLINE, pool[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        self.assertEmpty(pool[const.LISTENERS])
        self.assertEqual(const.LB_ALGORITHM_ROUND_ROBIN,
                         pool[const.LB_ALGORITHM])
        self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
        self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                         pool[const.SESSION_PERSISTENCE][const.TYPE])
        self.assertEqual(pool_sp_cookie_name,
                         pool[const.SESSION_PERSISTENCE][const.COOKIE_NAME])

        # Test that a user with lb_admin role can see the pool
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            pool_client = self.os_roles_lb_admin.pool_client
            pool_adm = pool_client.show_pool(pool[const.ID])
            self.assertEqual(pool_name, pool_adm[const.NAME])

        # Test that a user with cloud admin role can see the pool
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            adm = self.os_admin.pool_client.show_pool(
                pool[const.ID])
            self.assertEqual(pool_name, adm[const.NAME])

        # Test that a different user, with load balancer member role, cannot
        # see this pool
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.pool_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.show_pool,
                              pool[const.ID])

        # Test that a user, without the load balancer member role, cannot
        # show pools
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.pool_client.show_pool,
                pool[const.ID])

    @decorators.idempotent_id('7bd0a6bf-57b4-46a6-83ef-f9991896658a')
    def test_pool_update(self):
        """Tests pool update and show APIs.

        * Create a fully populated pool.
        * Show pool details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the pool.
        * Update the pool details.
        * Show pool details.
        * Validate the show reflects the updated values.
        """
        pool_name = data_utils.rand_name("lb_member_pool1-update")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name,
            },
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addClassResourceCleanup(
            self.mem_pool_client.cleanup_pool,
            pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        pool = waiters.wait_for_status(
            self.mem_pool_client.show_pool,
            pool[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(pool_name, pool[const.NAME])
        self.assertEqual(pool_description, pool[const.DESCRIPTION])
        self.assertFalse(pool[const.ADMIN_STATE_UP])
        parser.parse(pool[const.CREATED_AT])
        parser.parse(pool[const.UPDATED_AT])
        UUID(pool[const.ID])
        # Operating status for pools will always be offline without members
        self.assertEqual(const.OFFLINE, pool[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        self.assertEmpty(pool[const.LISTENERS])
        self.assertEqual(const.LB_ALGORITHM_ROUND_ROBIN,
                         pool[const.LB_ALGORITHM])
        self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
        self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                         pool[const.SESSION_PERSISTENCE][const.TYPE])
        self.assertEqual(pool_sp_cookie_name,
                         pool[const.SESSION_PERSISTENCE][const.COOKIE_NAME])

        # Test that a user, without the load balancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.pool_client.update_pool,
                pool[const.ID], admin_state_up=True)

        # Assert we didn't go into PENDING_*
        pool_check = self.mem_pool_client.show_pool(
            pool[const.ID])
        self.assertEqual(const.ACTIVE,
                         pool_check[const.PROVISIONING_STATUS])
        self.assertFalse(pool_check[const.ADMIN_STATE_UP])

        # Test that a user, without the load balancer member role, cannot
        # update this pool
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.pool_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.update_pool,
                              pool[const.ID], admin_state_up=True)

        # Assert we didn't go into PENDING_*
        pool_check = self.mem_pool_client.show_pool(
            pool[const.ID])
        self.assertEqual(const.ACTIVE,
                         pool_check[const.PROVISIONING_STATUS])
        self.assertFalse(pool_check[const.ADMIN_STATE_UP])

        new_name = data_utils.rand_name("lb_member_pool1-UPDATED")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        pool_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_HTTP_COOKIE,
            },
        }
        pool = self.mem_pool_client.update_pool(
            pool[const.ID], **pool_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        pool = waiters.wait_for_status(
            self.mem_pool_client.show_pool,
            pool[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(new_name, pool[const.NAME])
        self.assertEqual(new_description, pool[const.DESCRIPTION])
        self.assertTrue(pool[const.ADMIN_STATE_UP])
        self.assertEqual(const.LB_ALGORITHM_ROUND_ROBIN,
                         pool[const.LB_ALGORITHM])
        self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
        self.assertEqual(const.SESSION_PERSISTENCE_HTTP_COOKIE,
                         pool[const.SESSION_PERSISTENCE][const.TYPE])
        self.assertIsNone(
            pool[const.SESSION_PERSISTENCE].get(const.COOKIE_NAME))

        # Also test removing a Session Persistence
        pool_update_kwargs = {
            const.SESSION_PERSISTENCE: None,
        }
        pool = self.mem_pool_client.update_pool(
            pool[const.ID], **pool_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        pool = waiters.wait_for_status(
            self.mem_pool_client.show_pool,
            pool[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        self.assertIsNone(pool.get(const.SESSION_PERSISTENCE))

    @decorators.idempotent_id('35ed3800-7a4a-47a6-9b94-c1033fff1112')
    def test_pool_delete(self):
        """Tests pool create and delete APIs.

        * Creates a pool.
        * Validates that other accounts cannot delete the pool
        * Deletes the pool.
        * Validates the pool is in the DELETED state.
        """
        pool_name = data_utils.rand_name("lb_member_pool1-delete")
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: self.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.SESSION_PERSISTENCE: {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name,
            },
            const.LOADBALANCER_ID: self.lb_id,
        }
        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addClassResourceCleanup(
            self.mem_pool_client.cleanup_pool,
            pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the load balancer role cannot
        # delete this pool
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.pool_client.delete_pool,
                pool[const.ID])

        # Test that a different user, with the load balancer member role
        # cannot delete this pool
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.pool_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.delete_pool,
                              pool[const.ID])

        self.mem_pool_client.delete_pool(pool[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_pool_client.show_pool, pool[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
