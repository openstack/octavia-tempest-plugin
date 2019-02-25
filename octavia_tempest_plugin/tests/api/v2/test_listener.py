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
from oslo_utils import strutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class ListenerAPITest(test_base.LoadBalancerBaseTest):
    """Test the listener object API."""

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(ListenerAPITest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_listener")
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

    @decorators.idempotent_id('88d0ec83-7b08-48d9-96e2-0df1d2f8cd98')
    def test_listener_create(self):
        """Tests listener create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create listeners.
        * Create a fully populated listener.
        * Show listener details.
        * Validate the show reflects the requested values.
        """
        listener_name = data_utils.rand_name("lb_member_listener1-create")
        listener_description = data_utils.arbitrary_string(size=255)

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 80,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            const.INSERT_HEADERS: {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true"
            },
            # Don't test with a default pool -- we'll do that in the scenario,
            # but this will allow us to test that the field isn't mandatory,
            # as well as not conflate pool failures with listener test failures
            # const.DEFAULT_POOL_ID: self.pool_id,

            # TODO(rm_work): need to add TLS related stuff
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        # Test that a user without the load balancer role cannot
        # create a listener
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.listener_client.create_listener,
                **listener_kwargs)

        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.addClassResourceCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(listener_name, listener[const.NAME])
        self.assertEqual(listener_description, listener[const.DESCRIPTION])
        self.assertTrue(listener[const.ADMIN_STATE_UP])
        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, listener[const.PROTOCOL])
        self.assertEqual(80, listener[const.PROTOCOL_PORT])
        self.assertEqual(200, listener[const.CONNECTION_LIMIT])
        insert_headers = listener[const.INSERT_HEADERS]
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_FOR]))
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_PORT]))
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(1000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(50, listener[const.TIMEOUT_TCP_INSPECT])

    @decorators.idempotent_id('78ba6eb0-178c-477e-9156-b6775ca7b271')
    def test_listener_list(self):
        """Tests listener list API and field filtering.

        * Create a clean loadbalancer.
        * Create three listeners.
        * Validates that other accounts cannot list the listeners.
        * List the listeners using the default sort order.
        * List the listeners using descending sort order.
        * List the listeners using ascending sort order.
        * List the listeners returning one field at a time.
        * List the listeners returning two fields.
        * List the listeners filtering to one of the three.
        * List the listeners filtered, one field, and sorted.
        """
        lb_name = data_utils.rand_name("lb_member_lb2_listener-list")
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

        listener1_name = data_utils.rand_name("lb_member_listener2-list")
        listener1_desc = 'B'
        listener1_kwargs = {
            const.NAME: listener1_name,
            const.DESCRIPTION: listener1_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 80,
            const.LOADBALANCER_ID: lb_id,
        }
        listener1 = self.mem_listener_client.create_listener(
            **listener1_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener1[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        listener1 = waiters.wait_for_status(
            self.mem_listener_client.show_listener, listener1[const.ID],
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

        listener2_name = data_utils.rand_name("lb_member_listener1-list")
        listener2_desc = 'A'
        listener2_kwargs = {
            const.NAME: listener2_name,
            const.DESCRIPTION: listener2_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 81,
            const.LOADBALANCER_ID: lb_id,
        }
        listener2 = self.mem_listener_client.create_listener(
            **listener2_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener2[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        listener2 = waiters.wait_for_status(
            self.mem_listener_client.show_listener, listener2[const.ID],
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

        listener3_name = data_utils.rand_name("lb_member_listener3-list")
        listener3_desc = 'C'
        listener3_kwargs = {
            const.NAME: listener3_name,
            const.DESCRIPTION: listener3_desc,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 82,
            const.LOADBALANCER_ID: lb_id,
        }
        listener3 = self.mem_listener_client.create_listener(
            **listener3_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener3[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        listener3 = waiters.wait_for_status(
            self.mem_listener_client.show_listener, listener3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        if not CONF.load_balancer.test_with_noop:
            # Wait for the enabled listeners to come ONLINE
            listener1 = waiters.wait_for_status(
                self.mem_listener_client.show_listener, listener1[const.ID],
                const.OPERATING_STATUS, const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)
            listener2 = waiters.wait_for_status(
                self.mem_listener_client.show_listener, listener2[const.ID],
                const.OPERATING_STATUS, const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        # Test that a different user cannot list listeners
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.listener_client
            primary = member2_client.list_listeners(
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))
            self.assertEqual(0, len(primary))

        # Test that a user without the lb member role cannot list load
        # balancers
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.listener_client.list_listeners)

        # Check the default sort order, created_at
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener3[const.DESCRIPTION],
                         listeners[2][const.DESCRIPTION])

        # Test sort descending by description
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{sort}={descr}:{desc}'
                         .format(lb_id=lb_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, desc=const.DESC))
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[2][const.DESCRIPTION])
        self.assertEqual(listener3[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])

        # Test sort ascending by description
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{sort}={descr}:{asc}'
                         .format(lb_id=lb_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, asc=const.ASC))
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])
        self.assertEqual(listener3[const.DESCRIPTION],
                         listeners[2][const.DESCRIPTION])

        # Test fields
        show_listener_response_fields = const.SHOW_LISTENER_RESPONSE_FIELDS
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            show_listener_response_fields.append('timeout_client_data')
            show_listener_response_fields.append('timeout_member_connect')
            show_listener_response_fields.append('timeout_member_data')
            show_listener_response_fields.append('timeout_tcp_inspect')
        for field in show_listener_response_fields:
            if field in (const.DEFAULT_POOL_ID, const.L7_POLICIES):
                continue
            listeners = self.mem_listener_client.list_listeners(
                query_params='loadbalancer_id={lb_id}&{fields}={field}'
                             .format(lb_id=lb_id,
                                     fields=const.FIELDS, field=field))
            self.assertEqual(1, len(listeners[0]))
            self.assertEqual(listener1[field], listeners[0][field])
            self.assertEqual(listener2[field], listeners[1][field])
            self.assertEqual(listener3[field], listeners[2][field])

        # Test multiple fields at the same time
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{fields}={admin}&'
                         '{fields}={created}'.format(
                             lb_id=lb_id, fields=const.FIELDS,
                             admin=const.ADMIN_STATE_UP,
                             created=const.CREATED_AT))
        self.assertEqual(2, len(listeners[0]))
        self.assertTrue(listeners[0][const.ADMIN_STATE_UP])
        parser.parse(listeners[0][const.CREATED_AT])
        self.assertTrue(listeners[1][const.ADMIN_STATE_UP])
        parser.parse(listeners[1][const.CREATED_AT])
        self.assertFalse(listeners[2][const.ADMIN_STATE_UP])
        parser.parse(listeners[2][const.CREATED_AT])

        # Test filtering
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{desc}={lb_desc}'.format(
                lb_id=lb_id, desc=const.DESCRIPTION,
                lb_desc=listener2[const.DESCRIPTION]))
        self.assertEqual(1, len(listeners))
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])

        # Test combined params
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{admin}={true}&'
                         '{fields}={descr}&{fields}={id}&'
                         '{sort}={descr}:{desc}'.format(
                             lb_id=lb_id, admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, descr=const.DESCRIPTION,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        # Should get two listeners
        self.assertEqual(2, len(listeners))
        # listeners should have two fields
        self.assertEqual(2, len(listeners[0]))
        # Should be in descending order
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])

    @decorators.idempotent_id('6e299eae-6907-4dfc-89c2-e57709d25d3d')
    def test_listener_show(self):
        """Tests listener show API.

        * Create a fully populated listener.
        * Show listener details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the listener.
        """
        listener_name = data_utils.rand_name("lb_member_listener1-show")
        listener_description = data_utils.arbitrary_string(size=255)

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 81,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            const.INSERT_HEADERS: {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true"
            },
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_POOL_ID: '',
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.addClassResourceCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(listener_name, listener[const.NAME])
        self.assertEqual(listener_description, listener[const.DESCRIPTION])
        self.assertTrue(listener[const.ADMIN_STATE_UP])
        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, listener[const.PROTOCOL])
        self.assertEqual(81, listener[const.PROTOCOL_PORT])
        self.assertEqual(200, listener[const.CONNECTION_LIMIT])
        insert_headers = listener[const.INSERT_HEADERS]
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_FOR]))
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_PORT]))

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(1000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(50, listener[const.TIMEOUT_TCP_INSPECT])

        # Test that a user with lb_admin role can see the listener
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            listener_client = self.os_roles_lb_admin.listener_client
            listener_adm = listener_client.show_listener(listener[const.ID])
            self.assertEqual(listener_name, listener_adm[const.NAME])

        # Test that a user with cloud admin role can see the listener
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            adm = self.os_admin.listener_client.show_listener(
                listener[const.ID])
            self.assertEqual(listener_name, adm[const.NAME])

        # Test that a different user, with load balancer member role, cannot
        # see this listener
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.listener_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.show_listener,
                              listener[const.ID])

        # Test that a user, without the load balancer member role, cannot
        # show listeners
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.listener_client.show_listener,
                listener[const.ID])

    @decorators.idempotent_id('aaae0298-5778-4c7e-a27a-01549a71b319')
    def test_listener_update(self):
        """Tests listener update and show APIs.

        * Create a fully populated listener.
        * Show listener details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the listener.
        * Update the listener details.
        * Show listener details.
        * Validate the show reflects the updated values.
        """
        listener_name = data_utils.rand_name("lb_member_listener1-update")
        listener_description = data_utils.arbitrary_string(size=255)

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 82,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            const.INSERT_HEADERS: {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true"
            },
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_POOL_ID: '',
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.addClassResourceCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(listener_name, listener[const.NAME])
        self.assertEqual(listener_description, listener[const.DESCRIPTION])
        self.assertFalse(listener[const.ADMIN_STATE_UP])
        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status will be OFFLINE while admin_state_up = False
        self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, listener[const.PROTOCOL])
        self.assertEqual(82, listener[const.PROTOCOL_PORT])
        self.assertEqual(200, listener[const.CONNECTION_LIMIT])
        insert_headers = listener[const.INSERT_HEADERS]
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_FOR]))
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_PORT]))
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(1000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(50, listener[const.TIMEOUT_TCP_INSPECT])

        # Test that a user, without the load balancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.listener_client.update_listener,
                listener[const.ID], admin_state_up=True)

        # Assert we didn't go into PENDING_*
        listener_check = self.mem_listener_client.show_listener(
            listener[const.ID])
        self.assertEqual(const.ACTIVE,
                         listener_check[const.PROVISIONING_STATUS])
        self.assertFalse(listener_check[const.ADMIN_STATE_UP])

        # Test that a user, without the load balancer member role, cannot
        # update this listener
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.listener_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.update_listener,
                              listener[const.ID], admin_state_up=True)

        # Assert we didn't go into PENDING_*
        listener_check = self.mem_listener_client.show_listener(
            listener[const.ID])
        self.assertEqual(const.ACTIVE,
                         listener_check[const.PROVISIONING_STATUS])
        self.assertFalse(listener_check[const.ADMIN_STATE_UP])

        new_name = data_utils.rand_name("lb_member_listener1-UPDATED")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        listener_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.CONNECTION_LIMIT: 400,
            const.INSERT_HEADERS: {
                const.X_FORWARDED_FOR: "false",
                const.X_FORWARDED_PORT: "false"
            },
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_POOL_ID: '',
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_update_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 2000,
                const.TIMEOUT_MEMBER_CONNECT: 2000,
                const.TIMEOUT_MEMBER_DATA: 2000,
                const.TIMEOUT_TCP_INSPECT: 100,
            })

        listener = self.mem_listener_client.update_listener(
            listener[const.ID], **listener_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(new_name, listener[const.NAME])
        self.assertEqual(new_description, listener[const.DESCRIPTION])
        self.assertTrue(listener[const.ADMIN_STATE_UP])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])
        self.assertEqual(400, listener[const.CONNECTION_LIMIT])
        insert_headers = listener[const.INSERT_HEADERS]
        self.assertFalse(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_FOR]))
        self.assertFalse(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_PORT]))
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(2000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(100, listener[const.TIMEOUT_TCP_INSPECT])

    @decorators.idempotent_id('16f11c82-f069-4592-8954-81b35a98e3b7')
    def test_listener_delete(self):
        """Tests listener create and delete APIs.

        * Creates a listener.
        * Validates that other accounts cannot delete the listener
        * Deletes the listener.
        * Validates the listener is in the DELETED state.
        """
        listener_name = data_utils.rand_name("lb_member_listener1-delete")

        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 83,
            const.LOADBALANCER_ID: self.lb_id,
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.addClassResourceCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the load balancer role cannot
        # delete this listener
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.listener_client.delete_listener,
                listener[const.ID])

        # Test that a different user, with the load balancer member role
        # cannot delete this listener
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.listener_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.delete_listener,
                              listener[const.ID])

        self.mem_listener_client.delete_listener(listener[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_listener_client.show_listener, listener[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

    @decorators.idempotent_id('6f14a6c1-945e-43bc-8215-410c8a5edb25')
    def test_listener_show_stats(self):
        """Tests listener show statistics API.

        * Create a listener.
        * Validates that other accounts cannot see the stats for the
        *   listener.
        * Show listener statistics.
        * Validate the show reflects the expected values.
        """
        listener_name = data_utils.rand_name("lb_member_listener1-stats")
        listener_description = data_utils.arbitrary_string(size=255)

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: 84,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
        }

        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        # Test that a user, without the load balancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.listener_client.get_listener_stats,
                listener[const.ID])

        # Test that a different user, with the load balancer role, cannot see
        # the listener stats
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.listener_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.get_listener_stats,
                              listener[const.ID])

        stats = self.mem_listener_client.get_listener_stats(listener[const.ID])

        self.assertEqual(5, len(stats))
        self.assertEqual(0, stats[const.ACTIVE_CONNECTIONS])
        self.assertEqual(0, stats[const.BYTES_IN])
        self.assertEqual(0, stats[const.BYTES_OUT])
        self.assertEqual(0, stats[const.REQUEST_ERRORS])
        self.assertEqual(0, stats[const.TOTAL_CONNECTIONS])
