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
from oslo_utils import strutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

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
            cls.lb_id, cascade=True)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        cls.allowed_cidrs = ['192.0.1.0/24']
        if CONF.load_balancer.test_with_ipv6:
            cls.allowed_cidrs = ['2001:db8:a0b:12f0::/64']

    def _create_pools(cls, protocol, algorithm):
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            cls.mem_listener_client.is_version_supported(
                cls.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool1_name = data_utils.rand_name("lb_member_pool1_listener")
        pool1_kwargs = {
            const.NAME: pool1_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: cls.lb_id,
        }
        pool1 = cls.mem_pool_client.create_pool(**pool1_kwargs)
        pool1_id = pool1[const.ID]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool2_name = data_utils.rand_name("lb_member_pool2_listener")
        pool2_kwargs = {
            const.NAME: pool2_name,
            const.PROTOCOL: protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: cls.lb_id,
        }
        pool2 = cls.mem_pool_client.create_pool(**pool2_kwargs)
        pool2_id = pool2[const.ID]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        return pool1_id, pool2_id

    # Note: TERMINATED_HTTPS listeners are covered in a different
    #       tempest scenario suite due to the need for key-manager services

    @decorators.idempotent_id('ecdd65b0-cf8f-48ee-972b-2f09425472f1')
    def test_http_least_connections_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.HTTP,
                                          const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_listener_CRUD(const.HTTP, pool1, pool2)

    @decorators.idempotent_id('0681b2ac-8301-4e6c-bf29-b35244864af3')
    def test_tcp_least_connections_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.TCP,
                                          const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_listener_CRUD(const.TCP, pool1, pool2)

    @decorators.idempotent_id('27a2ba7d-6147-46e4-886a-47c1ba63bf89')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_least_connections_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.UDP,
                                          const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_listener_CRUD(const.UDP, pool1, pool2)

    @decorators.idempotent_id('4a874014-b7d1-49a4-ac9a-2400b3434700')
    def test_http_round_robin_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.HTTP,
                                          const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_listener_CRUD(const.HTTP, pool1, pool2)

    @decorators.idempotent_id('2b888812-d916-44f0-b620-8d83dbb45975')
    def test_tcp_round_robin_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.TCP,
                                          const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_listener_CRUD(const.TCP, pool1, pool2)

    @decorators.idempotent_id('dd913f74-c6a6-4998-9bed-095babb9cb47')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_round_robin_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.UDP,
                                          const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_listener_CRUD(const.UDP, pool1, pool2)

    @decorators.idempotent_id('b2ae8604-7a4f-477c-9658-fac27734671a')
    def test_http_source_ip_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.HTTP,
                                          const.LB_ALGORITHM_SOURCE_IP)
        self._test_listener_CRUD(const.HTTP, pool1, pool2)

    @decorators.idempotent_id('0ad3fdee-e8c2-4c44-9690-b8a838fbc7a5')
    def test_tcp_source_ip_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.TCP,
                                          const.LB_ALGORITHM_SOURCE_IP)
        self._test_listener_CRUD(const.TCP, pool1, pool2)

    @decorators.idempotent_id('7830aba8-12ca-40d9-9d9b-a63f7a43b287')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_source_ip_listener_CRUD(self):
        pool1, pool2 = self._create_pools(const.UDP,
                                          const.LB_ALGORITHM_SOURCE_IP)
        self._test_listener_CRUD(const.UDP, pool1, pool2)

    @decorators.idempotent_id('807a421e-5e99-4556-b0eb-512d39b25eac')
    def test_http_source_ip_port_listener_CRUD(self):
        try:
            pool1, pool2 = self._create_pools(
                const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)
            self._test_listener_CRUD(const.HTTP, pool1, pool2)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @decorators.idempotent_id('6211f8ad-622d-404d-b199-8c2eb55ab340')
    def test_tcp_source_ip_port_listener_CRUD(self):
        try:
            pool1, pool2 = self._create_pools(
                const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)
            self._test_listener_CRUD(const.TCP, pool1, pool2)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @decorators.idempotent_id('3f9a2de9-5012-437d-a907-a25e1f68ccfb')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_source_ip_port_listener_CRUD(self):
        try:
            pool1, pool2 = self._create_pools(
                const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)
            self._test_listener_CRUD(const.UDP, pool1, pool2)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    def _test_listener_CRUD(self, protocol, pool1_id, pool2_id):
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: 80,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            const.DEFAULT_POOL_ID: pool1_id,
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }

        if protocol in [const.HTTP, const.TERMINATED_HTTPS]:
            listener_kwargs.update({
                const.INSERT_HEADERS: {
                    const.X_FORWARDED_FOR: "true",
                    const.X_FORWARDED_PORT: "true"
                },
            })
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            listener_kwargs.update({const.ALLOWED_CIDRS: self.allowed_cidrs})

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
        self.assertEqual(protocol, listener[const.PROTOCOL])
        self.assertEqual(80, listener[const.PROTOCOL_PORT])
        self.assertEqual(200, listener[const.CONNECTION_LIMIT])
        if protocol in [const.HTTP, const.TERMINATED_HTTPS]:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
        self.assertEqual(pool1_id, listener[const.DEFAULT_POOL_ID])
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(1000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(50, listener[const.TIMEOUT_TCP_INSPECT])
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            self.assertEqual(self.allowed_cidrs, listener[const.ALLOWED_CIDRS])

        # Listener update
        new_name = data_utils.rand_name("lb_member_listener1-update")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        listener_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.CONNECTION_LIMIT: 400,
            const.DEFAULT_POOL_ID: pool2_id,
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if protocol in [const.HTTP, const.TERMINATED_HTTPS]:
            listener_update_kwargs.update({
                const.INSERT_HEADERS: {
                    const.X_FORWARDED_FOR: "false",
                    const.X_FORWARDED_PORT: "false"
                },
            })
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_update_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 2000,
                const.TIMEOUT_MEMBER_CONNECT: 2000,
                const.TIMEOUT_MEMBER_DATA: 2000,
                const.TIMEOUT_TCP_INSPECT: 100,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            new_cidrs = ['192.0.2.0/24']
            if CONF.load_balancer.test_with_ipv6:
                new_cidrs = ['2001:db8::/64']
            listener_update_kwargs.update({const.ALLOWED_CIDRS: new_cidrs})

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
        self.assertEqual(protocol, listener[const.PROTOCOL])
        self.assertEqual(80, listener[const.PROTOCOL_PORT])
        self.assertEqual(400, listener[const.CONNECTION_LIMIT])
        if protocol in [const.HTTP, const.TERMINATED_HTTPS]:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
        self.assertEqual(pool2_id, listener[const.DEFAULT_POOL_ID])
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(2000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(100, listener[const.TIMEOUT_TCP_INSPECT])
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            expected_cidrs = ['192.0.2.0/24']
            if CONF.load_balancer.test_with_ipv6:
                expected_cidrs = ['2001:db8::/64']
            self.assertEqual(expected_cidrs, listener[const.ALLOWED_CIDRS])

        # Listener delete
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
