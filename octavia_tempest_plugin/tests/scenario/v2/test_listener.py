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
from oslo_utils import strutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class ListenerScenarioTest(test_base.LoadBalancerBaseTest):

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(ListenerScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_listener")
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
        cls.protocol = const.HTTP
        lb_feature_enabled = CONF.loadbalancer_feature_enabled
        if not lb_feature_enabled.l7_protocol_enabled:
            cls.protocol = lb_feature_enabled.l4_protocol

        pool1_name = data_utils.rand_name("lb_member_pool1_listener")
        pool1_kwargs = {
            const.NAME: pool1_name,
            const.PROTOCOL: cls.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: cls.lb_id,
        }
        pool1 = cls.mem_pool_client.create_pool(**pool1_kwargs)
        cls.pool1_id = pool1[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_pool_client.cleanup_pool,
            cls.pool1_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool2_name = data_utils.rand_name("lb_member_pool2_listener")
        pool2_kwargs = {
            const.NAME: pool2_name,
            const.PROTOCOL: cls.protocol,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: cls.lb_id,
        }
        pool2 = cls.mem_pool_client.create_pool(**pool2_kwargs)
        cls.pool2_id = pool2[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_pool_client.cleanup_pool,
            cls.pool2_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

    @decorators.idempotent_id('4a874014-b7d1-49a4-ac9a-2400b3434700')
    def test_listener_CRUD(self):
        """Tests listener create, read, update, delete

        * Create a fully populated listener.
        * Show listener details.
        * Update the listener.
        * Delete the listener.
        """

        # Listener create
        listener_name = data_utils.rand_name("lb_member_listener1-CRUD")
        listener_description = data_utils.arbitrary_string(size=255)
        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: self.protocol,
            const.PROTOCOL_PORT: 80,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            const.INSERT_HEADERS: {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true"
            },
            const.DEFAULT_POOL_ID: self.pool1_id,
            # TODO(rm_work): need to finish the rest of this stuff
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

        self.assertEqual(listener_name, listener[const.NAME])
        self.assertEqual(listener_description, listener[const.DESCRIPTION])
        self.assertFalse(listener[const.ADMIN_STATE_UP])
        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status will be OFFLINE while admin_state_up = False
        self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        self.assertEqual(self.protocol, listener[const.PROTOCOL])
        self.assertEqual(80, listener[const.PROTOCOL_PORT])
        self.assertEqual(200, listener[const.CONNECTION_LIMIT])
        insert_headers = listener[const.INSERT_HEADERS]
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_FOR]))
        self.assertTrue(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_PORT]))
        self.assertEqual(self.pool1_id, listener[const.DEFAULT_POOL_ID])
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(1000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(50, listener[const.TIMEOUT_TCP_INSPECT])

        # Listener update
        new_name = data_utils.rand_name("lb_member_listener1-update")
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
            const.DEFAULT_POOL_ID: self.pool2_id,
            # TODO(rm_work): need to finish the rest of this stuff
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
        self.assertEqual(self.protocol, listener[const.PROTOCOL])
        self.assertEqual(80, listener[const.PROTOCOL_PORT])
        self.assertEqual(400, listener[const.CONNECTION_LIMIT])
        insert_headers = listener[const.INSERT_HEADERS]
        self.assertFalse(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_FOR]))
        self.assertFalse(
            strutils.bool_from_string(insert_headers[const.X_FORWARDED_PORT]))
        self.assertEqual(self.pool2_id, listener[const.DEFAULT_POOL_ID])
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(2000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(100, listener[const.TIMEOUT_TCP_INSPECT])

        # Listener delete
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        self.mem_listener_client.delete_listener(listener[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_listener_client.show_listener, listener[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
