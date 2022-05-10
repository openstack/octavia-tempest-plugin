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

    @classmethod
    def setup_clients(cls):
        """Setup client aliases."""
        super(ListenerAPITest, cls).setup_clients()
        cls.listener_client = cls.os_primary.load_balancer_v2.ListenerClient()
        cls.member2_listener_client = (
            cls.os_roles_lb_member2.load_balancer_v2.ListenerClient())

    @decorators.idempotent_id('88d0ec83-7b08-48d9-96e2-0df1d2f8cd98')
    def test_http_listener_create(self):
        self._test_listener_create(const.HTTP, 8000)

    @decorators.idempotent_id('2cc89237-fc6b-434d-b38e-b3309823e71f')
    def test_https_listener_create(self):
        self._test_listener_create(const.HTTPS, 8001)

    @decorators.idempotent_id('45580065-5653-436b-aaff-dc465fa0a542')
    def test_tcp_listener_create(self):
        self._test_listener_create(const.TCP, 8002)

    @decorators.idempotent_id('7b53f336-47bc-45ae-bbd7-4342ef0673fc')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_listener_create(self):
        self._test_listener_create(const.UDP, 8003)

    def _test_listener_create(self, protocol, protocol_port):
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            # Don't test with a default pool -- we'll do that in the scenario,
            # but this will allow us to test that the field isn't mandatory,
            # as well as not conflate pool failures with listener test failures
            # const.DEFAULT_POOL_ID: self.pool_id,

            # TODO(rm_work): need to add TLS related stuff
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if protocol == const.HTTP:
            listener_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true",
                const.X_FORWARDED_PROTO: "true",
            }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_tags = [str(x) for x in range(100)]
            listener_kwargs.update({
                const.TAGS: listener_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            # Test that CIDR IP version matches VIP IP version
            bad_cidrs = ['192.0.1.0/24', '2001:db8:a0b:12f0::/64']
            listener_kwargs.update({const.ALLOWED_CIDRS: bad_cidrs})
            self.assertRaises(
                exceptions.BadRequest,
                self.mem_listener_client.create_listener,
                **listener_kwargs)

            listener_kwargs.update({const.ALLOWED_CIDRS: self.allowed_cidrs})

        # Test that a user without the loadbalancer role cannot
        # create a listener.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'ListenerClient', 'create_listener',
                expected_allowed,
                status_method=self.mem_lb_client.show_loadbalancer,
                obj_id=self.lb_id, **listener_kwargs)

        listener = self.mem_listener_client.create_listener(**listener_kwargs)

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

        equal_items = [const.NAME, const.DESCRIPTION,
                       const.ADMIN_STATE_UP,
                       const.PROTOCOL, const.PROTOCOL_PORT,
                       const.CONNECTION_LIMIT]

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.TIMEOUT_CLIENT_DATA)
            equal_items.append(const.TIMEOUT_MEMBER_CONNECT)
            equal_items.append(const.TIMEOUT_MEMBER_DATA)
            equal_items.append(const.TIMEOUT_TCP_INSPECT)

        for item in equal_items:
            self.assertEqual(listener_kwargs[item], listener[item])

        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])

        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_kwargs[const.TAGS],
                                  listener[const.TAGS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            self.assertEqual(self.allowed_cidrs, listener[const.ALLOWED_CIDRS])

    @decorators.idempotent_id('cceac303-4db5-4d5a-9f6e-ff33780a5f29')
    def test_http_udp_tcp_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.HTTP, const.UDP,
                                                const.TCP, 8010)

    @decorators.idempotent_id('930338b8-3029-48a6-89b2-8b062060fe61')
    def test_http_udp_https_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.HTTP, const.UDP,
                                                const.HTTPS, 8011)

    @decorators.idempotent_id('01a21892-008a-4327-b4fd-fbf194ecb1a5')
    def test_tcp_udp_http_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.TCP, const.UDP,
                                                const.HTTP, 8012)

    @decorators.idempotent_id('5da764a4-c03a-46ed-848b-98b9d9fa9089')
    def test_tcp_udp_https_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.TCP, const.UDP,
                                                const.HTTPS, 8013)

    def _test_listener_create_on_same_port(self, protocol1, protocol2,
                                           protocol3, protocol_port):
        """Tests listener creation on same port number.

        * Create a first listener.
        * Create a new listener on an existing port, but with a different
          protocol.
        * Create a second listener with the same parameters and ensure that
          an error is triggered.
        * Create a third listener with another protocol over TCP, and ensure
          that it fails.
        """

        # Using listeners on the same port for TCP and UDP was not supported
        # before Train. Use 2.11 API version as reference to detect previous
        # releases and skip the test.
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.11'):
            raise self.skipException('TCP and UDP listeners on same port fix '
                                     'is only available on Octavia API '
                                     'version 2.11 or newer.')

        listener_name = data_utils.rand_name("lb_member_listener1-create")

        listener_kwargs = {
            const.NAME: listener_name,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol1,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200
        }

        try:
            self.mem_listener_client.create_listener(**listener_kwargs)
        except exceptions.BadRequest as e:
            faultstring = e.resp_body.get('faultstring', '')
            if ("Invalid input for field/attribute protocol." in faultstring
                    and "Value should be one of:" in faultstring):
                raise self.skipException("Skipping unsupported protocol")
            raise e

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Create a listener on the same port, but with a different protocol
        listener2_name = data_utils.rand_name("lb_member_listener2-create")

        listener2_kwargs = {
            const.NAME: listener2_name,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol2,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
        }

        try:
            self.mem_listener_client.create_listener(**listener2_kwargs)
        except exceptions.BadRequest as e:
            faultstring = e.resp_body.get('faultstring', '')
            if ("Invalid input for field/attribute protocol." in faultstring
                    and "Value should be one of:" in faultstring):
                raise self.skipException("Skipping unsupported protocol")
            raise e

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Create a listener on the same port, with an already used protocol
        listener3_name = data_utils.rand_name("lb_member_listener3-create")

        listener3_kwargs = {
            const.NAME: listener3_name,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol1,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
        }

        self.assertRaises(
            exceptions.Conflict,
            self.mem_listener_client.create_listener,
            **listener3_kwargs)

        # Create a listener on the same port, with another protocol over TCP
        listener4_name = data_utils.rand_name("lb_member_listener4-create")

        listener4_kwargs = {
            const.NAME: listener4_name,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol3,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
        }

        self.assertRaises(
            exceptions.Conflict,
            self.mem_listener_client.create_listener,
            **listener4_kwargs)

    @decorators.idempotent_id('78ba6eb0-178c-477e-9156-b6775ca7b271')
    def test_http_listener_list(self):
        self._test_listener_list(const.HTTP, 8020)

    @decorators.idempotent_id('61b7c643-f5fa-4471-8f9e-2e0ccdaf5ac7')
    def test_https_listener_list(self):
        self._test_listener_list(const.HTTPS, 8030)

    @decorators.idempotent_id('1cd476e2-7788-415e-bcaf-c377acfc9794')
    def test_tcp_listener_list(self):
        self._test_listener_list(const.TCP, 8030)

    @decorators.idempotent_id('c08fb77e-b317-4d6f-b430-91f5b27ebac6')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_listener_list(self):
        self._test_listener_list(const.UDP, 8040)

    def _test_listener_list(self, protocol, protocol_port_base):
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
        # IDs of listeners created in the test
        test_ids = []

        lb_name = data_utils.rand_name("lb_member_lb2_listener-list")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port_base,
            const.LOADBALANCER_ID: lb_id,
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener1_tags = ["English", "Mathematics",
                              "Marketing", "Creativity"]
            listener1_kwargs.update({const.TAGS: listener1_tags})

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
        test_ids.append(listener1[const.ID])
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port_base + 1,
            const.LOADBALANCER_ID: lb_id,
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener2_tags = ["English", "Spanish",
                              "Soft_skills", "Creativity"]
            listener2_kwargs.update({const.TAGS: listener2_tags})

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
        test_ids.append(listener2[const.ID])
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port_base + 2,
            const.LOADBALANCER_ID: lb_id,
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener3_tags = ["English", "Project_management",
                              "Communication", "Creativity"]
            listener3_kwargs.update({const.TAGS: listener3_tags})

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
        test_ids.append(listener3[const.ID])

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
            listener3 = waiters.wait_for_status(
                self.mem_listener_client.show_listener, listener3[const.ID],
                const.OPERATING_STATUS, const.OFFLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        # Test that a different users cannot see the lb_member listeners.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_primary', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_primary',
                                'os_roles_lb_member2', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_roles_lb_observer', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_list_RBAC_enforcement_count(
                'ListenerClient', 'list_listeners', expected_allowed, 0,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

        # Test credentials that should see these listeners can see them.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin', 'os_roles_lb_member',
                                'os_roles_lb_global_observer']
        if expected_allowed:
            self.check_list_IDs_RBAC_enforcement(
                'ListenerClient', 'list_listeners', expected_allowed,
                test_ids,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

        # Test that users without the lb member role cannot list listeners.
        # Note: non-owners can still call this API, they will just get the list
        #       of health monitors for their project (zero). The above tests
        #       are intended to cover the cross project use case.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_primary', 'os_roles_lb_admin',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        # Note: os_admin is here because it evaluaties to "project_admin"
        #       in oslo_policy and since keystone considers "project_admin"
        #       a superscope of "project_reader". This means it can read
        #       objects in the "admin" credential's project.
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_primary', 'os_system_admin',
                                'os_system_reader', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin', 'os_roles_lb_observer',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'ListenerClient', 'list_listeners', expected_allowed,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

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
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            show_listener_response_fields.append('allowed_cidrs')
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

        # Creating a list of 3 listeners, each one contains different tags
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            list_of_listeners = [listener1, listener2, listener3]
            test_list = []
            for listener in list_of_listeners:

                # If tags "English" and "Creativity" are in the listener's tags
                # and "Spanish" is not, add the listener to the list
                if "English" in listener[const.TAGS] and "Creativity" in (
                    listener[const.TAGS]) and "Spanish" not in (
                        listener[const.TAGS]):
                    test_list.append(listener[const.NAME])

            # Tests if only the first and the third ones have those tags
            self.assertEqual(
                test_list, [listener1[const.NAME], listener3[const.NAME]])

            # Tests that filtering by an empty tag will return an empty list
            self.assertTrue(not any(["" in listener[const.TAGS]
                                     for listener in list_of_listeners]))

    @decorators.idempotent_id('6e299eae-6907-4dfc-89c2-e57709d25d3d')
    def test_http_listener_show(self):
        self._test_listener_show(const.HTTP, 8050)

    @decorators.idempotent_id('aa838646-435f-4a20-8442-519a7a138e7e')
    def test_https_listener_show(self):
        self._test_listener_show(const.HTTPS, 8051)

    @decorators.idempotent_id('1fcbbee2-b697-4890-b6bf-d308ac1c94cd')
    def test_tcp_listener_show(self):
        self._test_listener_show(const.TCP, 8052)

    @decorators.idempotent_id('1dea3a6b-c95b-4e91-b591-1aa9cbcd0d1d')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_listener_show(self):
        self._test_listener_show(const.UDP, 8053)

    def _test_listener_show(self, protocol, protocol_port):
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_POOL_ID: '',
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if protocol == const.HTTP:
            listener_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true",
                const.X_FORWARDED_PROTO: "true",
            }

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_tags = ["hello", "world"]
            listener_kwargs.update({
                const.TAGS: listener_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            listener_kwargs.update({const.ALLOWED_CIDRS: self.allowed_cidrs})

        listener = self.mem_listener_client.create_listener(**listener_kwargs)

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
        equal_items = [const.NAME, const.DESCRIPTION,
                       const.ADMIN_STATE_UP,
                       const.PROTOCOL, const.PROTOCOL_PORT,
                       const.CONNECTION_LIMIT]

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.TIMEOUT_CLIENT_DATA)
            equal_items.append(const.TIMEOUT_MEMBER_CONNECT)
            equal_items.append(const.TIMEOUT_MEMBER_DATA)
            equal_items.append(const.TIMEOUT_TCP_INSPECT)

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_kwargs[const.TAGS],
                                  listener[const.TAGS])

        for item in equal_items:
            self.assertEqual(listener_kwargs[item], listener[item])

        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))

        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            self.assertEqual(self.allowed_cidrs, listener[const.ALLOWED_CIDRS])

        # Test that the appropriate users can see or not see the listener
        # based on the API RBAC.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'ListenerClient', 'show_listener',
                expected_allowed, listener[const.ID])

    @decorators.idempotent_id('aaae0298-5778-4c7e-a27a-01549a71b319')
    def test_http_listener_update(self):
        self._test_listener_update(const.HTTP, 8060)

    @decorators.idempotent_id('9679b061-2b2c-469f-abd9-26ed140ef001')
    def test_https_listener_update(self):
        self._test_listener_update(const.HTTPS, 8061)

    @decorators.idempotent_id('8d933121-db03-4ccc-8b77-4e879064a9ba')
    def test_tcp_listener_update(self):
        self._test_listener_update(const.TCP, 8062)

    @decorators.idempotent_id('fd02dbfd-39ce-41c2-b181-54fc7ad91707')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_listener_update(self):
        self._test_listener_update(const.UDP, 8063)

    def _test_listener_update(self, protocol, protocol_port):
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_POOL_ID: '',
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if protocol == const.HTTP:
            listener_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true",
                const.X_FORWARDED_PROTO: "true"
            }

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_tags = ["Hello", "World"]
            listener_kwargs.update({
                const.TAGS: listener_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            listener_kwargs.update({const.ALLOWED_CIDRS: self.allowed_cidrs})

        listener = self.mem_listener_client.create_listener(**listener_kwargs)

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
        self.assertEqual(protocol_port, listener[const.PROTOCOL_PORT])
        self.assertEqual(200, listener[const.CONNECTION_LIMIT])
        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(1000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(50, listener[const.TIMEOUT_TCP_INSPECT])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_kwargs[const.TAGS],
                                  listener[const.TAGS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            self.assertEqual(self.allowed_cidrs, listener[const.ALLOWED_CIDRS])

        # Test that a user without the loadbalancer role cannot
        # update a listener.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'ListenerClient', 'update_listener',
                expected_allowed,
                status_method=self.mem_listener_client.show_listener,
                obj_id=listener[const.ID], listener_id=listener[const.ID],
                admin_state_up=True)

        new_name = data_utils.rand_name("lb_member_listener1-UPDATED")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        listener_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.CONNECTION_LIMIT: 400,
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_POOL_ID: '',
            # const.DEFAULT_TLS_CONTAINER_REF: '',
            # const.SNI_CONTAINER_REFS: [],
        }
        if protocol == const.HTTP:
            listener_update_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "false",
                const.X_FORWARDED_PORT: "false",
                const.X_FORWARDED_PROTO: "false"
            }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_update_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 2000,
                const.TIMEOUT_MEMBER_CONNECT: 2000,
                const.TIMEOUT_MEMBER_DATA: 2000,
                const.TIMEOUT_TCP_INSPECT: 100,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_updated_tags = ["Hola", "Mundo"]
            listener_update_kwargs.update({
                const.TAGS: listener_updated_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            # Test that CIDR IP version matches VIP IP version
            bad_cidrs = ['192.0.2.0/24', '2001:db8::/6']
            listener_update_kwargs.update({const.ALLOWED_CIDRS: bad_cidrs})
            self.assertRaises(
                exceptions.BadRequest,
                self.mem_listener_client.update_listener,
                listener[const.ID], **listener_update_kwargs)

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
        self.assertEqual(400, listener[const.CONNECTION_LIMIT])
        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(2000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(100, listener[const.TIMEOUT_TCP_INSPECT])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_update_kwargs[const.TAGS],
                                  listener[const.TAGS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            expected_cidrs = ['192.0.2.0/24']
            if CONF.load_balancer.test_with_ipv6:
                expected_cidrs = ['2001:db8::/64']
            self.assertEqual(expected_cidrs, listener[const.ALLOWED_CIDRS])

    @decorators.idempotent_id('16f11c82-f069-4592-8954-81b35a98e3b7')
    def test_http_listener_delete(self):
        self._test_listener_delete(const.HTTP, 8070)

    @decorators.idempotent_id('769526a0-df71-47cd-996e-46484de32223')
    def test_https_listener_delete(self):
        self._test_listener_delete(const.HTTPS, 8071)

    @decorators.idempotent_id('f5ca019d-2b33-48f9-9c2d-2ec169b423ca')
    def test_tcp_listener_delete(self):
        self._test_listener_delete(const.TCP, 8072)

    @decorators.idempotent_id('86bd9717-e3e9-41e3-86c4-888c64455926')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_listener_delete(self):
        self._test_listener_delete(const.UDP, 8073)

    def _test_listener_delete(self, protocol, protocol_port):
        """Tests listener create and delete APIs.

        * Creates a listener.
        * Validates that other accounts cannot delete the listener
        * Deletes the listener.
        * Validates the listener is in the DELETED state.
        """
        listener_name = data_utils.rand_name("lb_member_listener1-delete")

        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the loadbalancer role cannot
        # delete a listener.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'ListenerClient', 'delete_listener',
                expected_allowed,
                status_method=self.mem_listener_client.show_listener,
                obj_id=listener[const.ID], listener_id=listener[const.ID])

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
    def test_http_listener_show_stats(self):
        self._test_listener_show_stats(const.HTTP, 8080)

    @decorators.idempotent_id('f8a43c27-f0a0-496d-a287-1958f337ac04')
    def test_https_listener_show_stats(self):
        self._test_listener_show_stats(const.HTTPS, 8081)

    @decorators.idempotent_id('8a999856-f448-498c-b891-21af449b5208')
    def test_tcp_listener_show_stats(self):
        self._test_listener_show_stats(const.TCP, 8082)

    @decorators.idempotent_id('a4c1f199-923b-41e4-a134-c91e590e20c4')
    # Skipping due to a status update bug in the amphora driver.
    @decorators.skip_because(
        bug='2007979',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_udp_listener_show_stats(self):
        self._test_listener_show_stats(const.UDP, 8083)

    def _test_listener_show_stats(self, protocol, protocol_port):
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
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
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
                self.listener_client.get_listener_stats,
                listener[const.ID])

        # Test that a different user, with the load balancer role, cannot see
        # the listener stats
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.member2_listener_client
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
