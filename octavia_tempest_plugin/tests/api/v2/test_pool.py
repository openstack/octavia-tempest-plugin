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

    # Pool with Least Connections algorithm
    @decorators.idempotent_id('29f1a69d-6a0d-4a85-b178-f50f5b4bdfbc')
    def test_HTTP_LC_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTP, protocol_port=10,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('5086402a-2339-4238-bddb-d30508e6cc53')
    def test_HTTP_LC_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTP,
                               pool_protocol=const.HTTP, protocol_port=11,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('eb84fabc-68e6-44f7-955d-4919f045cd08')
    def test_HTTPS_LC_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTPS, protocol_port=12,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('664fc4d3-70d9-41c5-b3f8-c006726062ae')
    def test_HTTPS_LC_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTPS,
                               pool_protocol=const.HTTPS, protocol_port=13,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('08e35f78-a85d-48d2-8ac3-14c5e68b64f7')
    def test_PROXY_LC_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.PROXY, protocol_port=14,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('044f460b-47ec-4e97-96be-c7ab812bfa16')
    def test_PROXY_LC_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.PROXY, protocol_port=15,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('8f552da6-38f8-44b8-b69b-072cc1e232a6')
    def test_TCP_LC_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.TCP, protocol_port=16,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('728b974f-ff59-479b-ada5-de280bbaaf02')
    def test_TCP_LC_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.TCP, protocol_port=17,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('0cb032d9-e092-476e-9aaf-463eea58fc16')
    def test_UDP_LC_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.UDP, protocol_port=18,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('9bf3bb05-ee36-47f3-b669-78f06a94035d')
    def test_UDP_LC_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.UDP,
                               pool_protocol=const.UDP, protocol_port=19,
                               algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    # Pool with Round Robin algorithm
    @decorators.idempotent_id('7587fe48-87ba-4538-9f03-190911f100ff')
    def test_HTTP_RR_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTP, protocol_port=20,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('c9c0df79-f07e-428c-ae57-b9d4078eec79')
    def test_HTTP_RR_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTP,
                               pool_protocol=const.HTTP, protocol_port=21,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('cc940a8b-b21c-46f5-9976-d2c8dd73b626')
    def test_HTTPS_RR_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTPS, protocol_port=22,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('10df2793-63b2-42a3-a5d0-9241a9d700a3')
    def test_HTTPS_RR_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTPS,
                               pool_protocol=const.HTTPS, protocol_port=23,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('4d6c124e-73ea-4b32-bd1c-3ff7be2c4e55')
    def test_PROXY_RR_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.PROXY, protocol_port=24,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('60406086-b0a9-4f55-8f64-df161981443c')
    def test_PROXY_RR_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.PROXY, protocol_port=25,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('41a5f22e-80e8-4d85-bfd6-2726846ed2ce')
    def test_TCP_RR_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.TCP, protocol_port=26,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('b76432ae-1aa2-4048-b326-1cbda28415ac')
    def test_TCP_RR_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.TCP, protocol_port=27,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('c09be35d-8a8b-4abd-8752-2cb4d7d7fab2')
    def test_UDP_RR_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.UDP, protocol_port=28,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('4fb59ed9-5c44-437e-a5f9-bb01b9ba6a72')
    def test_UDP_RR_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.UDP,
                               pool_protocol=const.UDP, protocol_port=29,
                               algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    # Pool with Source IP algorithm
    @decorators.idempotent_id('a8b1b41c-5c3c-4c17-a2d4-b7c344520e3d')
    def test_HTTP_SI_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTP, protocol_port=30,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('0136341c-4622-4f65-a59d-b9983331d627')
    def test_HTTP_SI_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTP,
                               pool_protocol=const.HTTP, protocol_port=31,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('d69c5e0b-43b5-4afe-a94a-1a4f93e44a93')
    def test_HTTPS_SI_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTPS, protocol_port=32,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('04cc43f2-9eab-4552-b8c1-cea9e1325696')
    def test_HTTPS_SI_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTPS,
                               pool_protocol=const.HTTPS, protocol_port=33,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('cc42779d-71f8-4a7c-8217-02127be344ce')
    def test_PROXY_SI_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.PROXY, protocol_port=34,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('c845d8d3-30d7-42c3-8943-9a4582c62e2d')
    def test_PROXY_SI_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.PROXY, protocol_port=35,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('869b4208-5821-44f5-acf6-4f087c4dd79c')
    def test_TCP_SI_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.TCP, protocol_port=36,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('4b0be593-b2e4-4704-a347-c36dae76aaad')
    def test_TCP_SI_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.TCP, protocol_port=37,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('47af95cb-685a-48de-9d17-66108cdfd3fa')
    def test_UDP_SI_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.UDP, protocol_port=38,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('0115ab0c-e8fd-434a-9448-7fba55a8f27d')
    def test_UDP_SI_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.UDP,
                               pool_protocol=const.UDP, protocol_port=39,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP)

    # Pool with Source IP Port algorithm
    @decorators.idempotent_id('265ba978-a528-429c-9ef7-c36373ee2225')
    def test_HTTP_SIP_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTP, protocol_port=40,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('a07e2ff0-90f3-43d3-a7ec-5ca93b7f29bf')
    def test_HTTP_SIP_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTP,
                               pool_protocol=const.HTTP, protocol_port=41,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('7da08af5-e225-46df-b0b4-a5f1834a5377')
    def test_HTTPS_SIP_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.HTTPS, protocol_port=42,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('3d52a82e-e488-445a-8599-87e9bb7153eb')
    def test_HTTPS_SIP_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.HTTPS,
                               pool_protocol=const.HTTPS, protocol_port=43,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('ad4cb862-fa37-4874-99c1-511cdcd86f91')
    def test_PROXY_SIP_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.PROXY, protocol_port=44,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('bcf76f26-e801-4ab4-b338-b210457d592e')
    def test_PROXY_SIP_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.PROXY, protocol_port=45,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('42382080-7fd5-46d7-afd7-d47c880f0397')
    def test_TCP_SIP_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.TCP, protocol_port=46,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('53687dd3-e076-4e93-b917-93c76a160444')
    def test_TCP_SIP_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.TCP,
                               pool_protocol=const.TCP, protocol_port=47,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('02d40127-d46e-4aba-8428-96f6deff3554')
    def test_UDP_SIP_pool_standalone_create(self):
        self._test_pool_create(listener_protocol=None,
                               pool_protocol=const.UDP, protocol_port=48,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('5f1acd3e-305d-40d5-81e9-fe6250411d49')
    def test_UDP_SIP_pool_with_listener_create(self):
        self._test_pool_create(listener_protocol=const.UDP,
                               pool_protocol=const.UDP, protocol_port=49,
                               algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    # Test with session persistence
    @decorators.idempotent_id('c8b84032-1c20-4d85-9db2-2fe5b9eff37a')
    def test_HTTP_RR_app_cookie_pool_with_listener_create(self):
        self._test_pool_create(
            listener_protocol=const.HTTP,
            pool_protocol=const.HTTP, protocol_port=50,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_APP_COOKIE)

    @decorators.idempotent_id('0296cccb-83be-425c-ac6a-828774734d5a')
    def test_HTTP_RR_http_cookie_pool_with_listener_create(self):
        self._test_pool_create(
            listener_protocol=const.HTTP,
            pool_protocol=const.HTTP, protocol_port=51,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_HTTP_COOKIE)

    @decorators.idempotent_id('882263e6-d50f-47b4-9083-f76c2b92eef0')
    def test_HTTP_RR_source_IP_pool_with_listener_create(self):
        self._test_pool_create(
            listener_protocol=const.HTTP,
            pool_protocol=const.HTTP, protocol_port=52,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    @decorators.idempotent_id('1d5eed30-86bf-4bf4-87d0-22adee3defa1')
    def test_UDP_RR_source_ip_pool_with_listener_create(self):
        self._test_pool_create(
            listener_protocol=const.UDP,
            pool_protocol=const.UDP, protocol_port=53,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    def _test_pool_create(self, listener_protocol, pool_protocol,
                          protocol_port, algorithm, session_persistence=None):
        """Tests pool create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create pools.
        * Create a fully populated pool.
        * Show pool details.
        * Validate the show reflects the requested values.
        """
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        if listener_protocol is not None:
            listener_name = data_utils.rand_name("lb_member_listener1_pool")
            listener_kwargs = {
                const.NAME: listener_name,
                const.PROTOCOL: listener_protocol,
                const.PROTOCOL_PORT: protocol_port,
                const.LOADBALANCER_ID: self.lb_id,
            }
            listener = self.mem_listener_client.create_listener(
                **listener_kwargs)

            waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                    self.lb_id, const.PROVISIONING_STATUS,
                                    const.ACTIVE,
                                    CONF.load_balancer.build_interval,
                                    CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1-create")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
        }

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            pool_tags = ["Hello", "World"]
            pool_kwargs.update({
                const.TAGS: pool_tags
            })

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name
            }
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_HTTP_COOKIE
            }
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_SOURCE_IP
            }

        if listener_protocol is not None:
            pool_kwargs[const.LISTENER_ID] = listener[const.ID]
        else:
            pool_kwargs[const.LOADBALANCER_ID] = self.lb_id

        # Test that a user without the loadbalancer role cannot
        # create a pool.
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
                'PoolClient', 'create_pool',
                expected_allowed,
                status_method=self.mem_lb_client.show_loadbalancer,
                obj_id=self.lb_id, **pool_kwargs)

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

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
        if (listener_protocol is not None and
                not CONF.load_balancer.test_with_noop):
            pool = waiters.wait_for_status(
                self.mem_pool_client.show_pool,
                pool[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)
        else:
            self.assertEqual(const.OFFLINE, pool[const.OPERATING_STATUS])

        self.assertEqual(pool_name, pool[const.NAME])
        self.assertEqual(pool_description, pool[const.DESCRIPTION])
        self.assertTrue(pool[const.ADMIN_STATE_UP])
        parser.parse(pool[const.CREATED_AT])
        parser.parse(pool[const.UPDATED_AT])
        UUID(pool[const.ID])
        # Operating status for a pool without members will be:
        if (listener_protocol is not None and
                not CONF.load_balancer.test_with_noop):
            # ONLINE if it is attached to a listener and is a live test
            self.assertEqual(const.ONLINE, pool[const.OPERATING_STATUS])
        else:
            # OFFLINE if it is just on the LB directly or is in noop mode
            self.assertEqual(const.OFFLINE, pool[const.OPERATING_STATUS])
        self.assertEqual(pool_protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        if listener_protocol is not None:
            self.assertEqual(1, len(pool[const.LISTENERS]))
            self.assertEqual(listener[const.ID],
                             pool[const.LISTENERS][0][const.ID])
        else:
            self.assertEmpty(pool[const.LISTENERS])
        self.assertEqual(algorithm, pool[const.LB_ALGORITHM])

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
            self.assertEqual(pool_sp_cookie_name,
                             pool[const.SESSION_PERSISTENCE][
                                 const.COOKIE_NAME])
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_HTTP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_SOURCE_IP,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            self.assertCountEqual(pool_kwargs[const.TAGS],
                                  pool[const.TAGS])

    @decorators.idempotent_id('4b4c8021-f4dd-4826-b825-7e3dc0beaba4')
    def test_HTTP_LC_pool_list(self):
        self._test_pool_list(const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('6959a32e-fb34-4f3e-be68-8880c6450016')
    def test_HTTP_RR_pool_list(self):
        self._test_pool_list(const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('b2cb9879-c1b3-491a-bd20-773bc57625b0')
    def test_HTTP_SI_pool_list(self):
        self._test_pool_list(const.HTTP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('871b5a7f-c8f3-4d05-9533-f9498e2465fa')
    def test_HTTP_SIP_pool_list(self):
        self._test_pool_list(const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('8ace3b65-7183-4b55-837d-3e7f438ea079')
    def test_HTTPS_LC_pool_list(self):
        self._test_pool_list(const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('7e01fa71-34fd-42e6-9db8-4b2a57cda38d')
    def test_HTTPS_RR_pool_list(self):
        self._test_pool_list(const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('25d4b0d2-ab46-40ad-afec-1b0afa88a559')
    def test_HTTPS_SI_pool_list(self):
        self._test_pool_list(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('250e6bf6-5017-47c9-ae12-1e64515d3bfd')
    def test_HTTPS_SIP_pool_list(self):
        self._test_pool_list(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('f3f3565e-a6b3-4541-9fb3-d9900231771b')
    def test_PROXY_LC_pool_list(self):
        self._test_pool_list(const.PROXY, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('fb267dae-b4e3-4858-a85e-72ecb1d91eff')
    def test_PROXY_RR_pool_list(self):
        self._test_pool_list(const.PROXY, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('42a3e3e3-ad71-418e-a262-628a213a7b03')
    def test_PROXY_SI_pool_list(self):
        self._test_pool_list(const.PROXY, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('69d3f811-6ce8-403e-bae9-745d51cb268a')
    def test_PROXY_SIP_pool_list(self):
        self._test_pool_list(const.PROXY, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('f3a74c0c-3083-44a5-9938-a245176babcd')
    def test_TCP_LC_pool_list(self):
        self._test_pool_list(const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('1a0b616f-ee77-4ac1-bb5f-300c2a10a7f2')
    def test_TCP_RR_pool_list(self):
        self._test_pool_list(const.TCP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('ec0fda75-f2d7-4fa6-ba91-c5eb9a7e9874')
    def test_TCP_SI_pool_list(self):
        self._test_pool_list(const.TCP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('8ca217d0-705f-4a7a-87c2-752bb1ee88f1')
    def test_TCP_SIP_pool_list(self):
        self._test_pool_list(const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('ed26899d-a590-46fc-bf70-27c5a9c59cbf')
    def test_UDP_LC_pool_list(self):
        self._test_pool_list(const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('6fb6a6e3-ff65-4f2c-8876-2997d3903cfe')
    def test_UDP_RR_pool_list(self):
        self._test_pool_list(const.UDP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('0bb02800-d7c9-4916-a532-ac1ac7b945d0')
    def test_UDP_SI_pool_list(self):
        self._test_pool_list(const.UDP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('bdc7df5f-ffdb-48c8-823e-a3b5d76868a0')
    def test_UDP_SIP_pool_list(self):
        self._test_pool_list(const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    def _test_pool_list(self, pool_protocol, algorithm):
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
        # IDs of pools created in the test
        test_ids = []

        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        lb_name = data_utils.rand_name("lb_member_lb2_pool-list")
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

        pool1_name = data_utils.rand_name("lb_member_pool2-list")
        pool1_desc = 'B'
        pool1_kwargs = {
            const.NAME: pool1_name,
            const.DESCRIPTION: pool1_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: lb_id,
        }

        if self.mem_pool_client.is_version_supported(
                self.api_version, '2.5'):
            pool1_tags = ["English", "Mathematics",
                          "Marketing", "Creativity"]
            pool1_kwargs.update({const.TAGS: pool1_tags})

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool1 = self.mem_pool_client.create_pool(**pool1_kwargs)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

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
        test_ids.append(pool1[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        pool2_name = data_utils.rand_name("lb_member_pool1-list")
        pool2_desc = 'A'
        pool2_kwargs = {
            const.NAME: pool2_name,
            const.DESCRIPTION: pool2_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: lb_id,
        }

        if self.mem_pool_client.is_version_supported(
                self.api_version, '2.5'):
            pool2_tags = ["English", "Spanish",
                          "Soft_skills", "Creativity"]
            pool2_kwargs.update({const.TAGS: pool2_tags})

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
        test_ids.append(pool2[const.ID])
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
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: lb_id,
        }

        if self.mem_pool_client.is_version_supported(
                self.api_version, '2.5'):
            pool3_tags = ["English", "Project_management",
                          "Communication", "Creativity"]
            pool3_kwargs.update({const.TAGS: pool3_tags})

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
        test_ids.append(pool3[const.ID])

        # Test that a different users cannot see the lb_member pools.
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
                'PoolClient', 'list_pools', expected_allowed, 0,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

        # Test credentials that should see these pools can see them.
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
                'PoolClient', 'list_pools', expected_allowed, test_ids,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

        # Test that users without the lb member role cannot list pools.
        # Note: non-owners can still call this API, they will just get the list
        #       of pools for their project (zero). The above tests
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
                'PoolClient', 'list_pools', expected_allowed,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

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

        # Creating a list of 3 pools, each one contains different tags
        if self.mem_pool_client.is_version_supported(
                self.api_version, '2.5'):
            list_of_pools = [pool1, pool2, pool3]
            test_list = []
            for pool in list_of_pools:

                # If tags "English" and "Creativity" are in the pool's tags
                # and "Spanish" is not, add the pool to the list
                if "English" in pool[const.TAGS] and "Creativity" in (
                    pool[const.TAGS]) and "Spanish" not in (
                        pool[const.TAGS]):
                    test_list.append(pool[const.NAME])

            # Tests if only the first and the third ones have those tags
            self.assertEqual(
                test_list, [pool1[const.NAME], pool3[const.NAME]])

            # Tests that filtering by an empty tag will return an empty list
            self.assertTrue(not any(["" in pool[const.TAGS]
                                     for pool in list_of_pools]))

    @decorators.idempotent_id('416c72c6-ef63-4e70-b27e-3ed95b93c02d')
    def test_HTTP_LC_pool_show(self):
        self._test_pool_show(const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('82568809-bdb9-444b-9790-128d0c328d72')
    def test_HTTPS_LC_pool_show(self):
        self._test_pool_show(const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('93e4bc67-ce12-43fb-a50d-97de47c3a63f')
    def test_PROXY_LC_pool_show(self):
        self._test_pool_show(const.PROXY, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('ee910c1e-1704-4b41-99c1-0c1f904e577d')
    def test_TCP_LC_pool_show(self):
        self._test_pool_show(const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('5f4339f6-0387-44f4-a5f9-e385d44b5ee2')
    def test_UDP_LC_pool_show(self):
        self._test_pool_show(const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('b7932438-1aea-4175-a50c-984fee1c0cad')
    def test_HTTP_RR_pool_show(self):
        self._test_pool_show(const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('a1bffe2f-ce20-4d79-a168-bc930de5edcb')
    def test_HTTPS_RR_pool_show(self):
        self._test_pool_show(const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('4cf9fa5c-d8e0-4253-8b79-2eb59e066772')
    def test_PROXY_RR_pool_show(self):
        self._test_pool_show(const.PROXY, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('e6e91bb3-76b3-4ff8-ad60-d20ac1e64381')
    def test_TCP_RR_pool_show(self):
        self._test_pool_show(const.TCP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('7c4a1c90-7fc2-42ee-ad78-d7c75b5a56d2')
    def test_UDP_RR_pool_show(self):
        self._test_pool_show(const.UDP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('af1c1b10-a6ac-4f28-82ba-2c0770903a5c')
    def test_HTTP_SI_pool_show(self):
        self._test_pool_show(const.HTTP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('64434a6d-222e-4056-bcc0-335ebe4f03ee')
    def test_HTTPS_SI_pool_show(self):
        self._test_pool_show(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('adbb7f3b-7a37-4a8e-a2b4-c3f827dad0ba')
    def test_PROXY_SI_pool_show(self):
        self._test_pool_show(const.PROXY, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('55f62d1a-33b0-4263-84af-672a30ee52bd')
    def test_TCP_SI_pool_show(self):
        self._test_pool_show(const.TCP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('5b961eee-183d-435c-bdf5-b83ca68c4944')
    def test_UDP_SI_pool_show(self):
        self._test_pool_show(const.UDP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('59964666-3dfe-4bad-81e0-bc5a4809c10c')
    def test_HTTP_SIP_pool_show(self):
        self._test_pool_show(const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('9f8f855c-cd09-4a74-b5f2-c5c13b59422e')
    def test_HTTPS_SIP_pool_show(self):
        self._test_pool_show(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('1194bd18-20bc-43e7-b588-9f78a72e0021')
    def test_PROXY_SIP_pool_show(self):
        self._test_pool_show(const.PROXY, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('6003cbe8-73a5-416a-9be0-7aa5699dc157')
    def test_TCP_SIP_pool_show(self):
        self._test_pool_show(const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('1400529e-3a0c-4bac-b6ed-669fdd723956')
    def test_UDP_SIP_pool_show(self):
        self._test_pool_show(const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    # Test with session persistence
    @decorators.idempotent_id('6fa12ae6-a61a-43d0-85d7-5367811c9c5a')
    def test_HTTP_RR_app_cookie_pool_show(self):
        self._test_pool_show(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_APP_COOKIE)

    @decorators.idempotent_id('4a1b6e2c-c216-4589-9ab6-2cd63217f06a')
    def test_HTTP_RR_http_cookie_pool_show(self):
        self._test_pool_show(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_HTTP_COOKIE)

    @decorators.idempotent_id('373f1c80-e51e-4260-b8d8-f6aeb512f81c')
    def test_HTTP_RR_source_IP_pool_show(self):
        self._test_pool_show(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    @decorators.idempotent_id('bd732c36-bdaa-4591-bf4e-28268874d22c')
    def test_UDP_RR_source_IP_pool_show(self):
        self._test_pool_show(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    def _test_pool_show(self, pool_protocol, algorithm,
                        session_persistence=None):
        """Tests pool show API.

        * Create a fully populated pool.
        * Show pool details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the pool.
        """
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1-show")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name
            }
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_HTTP_COOKIE
            }
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_SOURCE_IP
            }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

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
        self.assertEqual(pool_protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        self.assertEmpty(pool[const.LISTENERS])
        self.assertEqual(algorithm, pool[const.LB_ALGORITHM])

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
            self.assertEqual(pool_sp_cookie_name,
                             pool[const.SESSION_PERSISTENCE][
                                 const.COOKIE_NAME])
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_HTTP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_SOURCE_IP,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])

        # Test that the appropriate users can see or not see the pool
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
                'PoolClient', 'show_pool',
                expected_allowed, pool[const.ID])

    @decorators.idempotent_id('d73755fe-ba3a-4248-9543-8e167a5aa7f4')
    def test_HTTP_LC_pool_update(self):
        self._test_pool_update(const.HTTP,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('ca641999-7817-4f8f-a58b-2ccd7a5dca97')
    def test_HTTPS_LC_pool_update(self):
        self._test_pool_update(const.HTTPS,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('67a2cbab-f4fc-41c8-93e8-97ddba39c1ab')
    def test_PROXY_LC_pool_update(self):
        self._test_pool_update(const.PROXY,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('c9f1ed23-f6d4-4d44-9d22-bdc1fbe5854d')
    def test_TCP_LC_pool_update(self):
        self._test_pool_update(const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('8e6b8802-c4a7-43eb-a4e8-9f6bf7899a7d')
    def test_UDP_LC_pool_update(self):
        self._test_pool_update(const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('7bd0a6bf-57b4-46a6-83ef-f9991896658a')
    def test_HTTP_RR_pool_update(self):
        self._test_pool_update(const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('ac097c2e-4f79-4714-8de4-517598d37919')
    def test_HTTPS_RR_pool_update(self):
        self._test_pool_update(const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('4392bc21-c18e-4e25-bb7e-2c9e3777d784')
    def test_PROXY_RR_pool_update(self):
        self._test_pool_update(const.PROXY, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('f6a5970d-2f27-419b-a0ee-7a420ee7b396')
    def test_TCP_RR_pool_update(self):
        self._test_pool_update(const.TCP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('a1cded67-9fd6-4155-8761-ce165d518b47')
    def test_UDP_RR_pool_update(self):
        self._test_pool_update(const.UDP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('42a742d2-ef9c-47fd-8585-5588bb867431')
    def test_HTTP_SI_pool_update(self):
        self._test_pool_update(const.HTTP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('3b4e6462-4e0c-4c05-bc30-d6f86f67bb60')
    def test_HTTPS_SI_pool_update(self):
        self._test_pool_update(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('d2cb7a0a-8268-46bc-a519-08474c42c4ca')
    def test_PROXY_SI_pool_update(self):
        self._test_pool_update(const.PROXY, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('84e63663-0bf7-45bc-a4d9-b3bbd664fd8c')
    def test_TCP_SI_pool_update(self):
        self._test_pool_update(const.TCP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('cdb230b9-996a-4933-a7a2-a7b09465c18c')
    def test_UDP_SI_pool_update(self):
        self._test_pool_update(const.UDP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('7c770af5-782e-453c-bd2e-41ec90b37907')
    def test_HTTP_SIP_pool_update(self):
        self._test_pool_update(const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('72cee49d-36d5-4b54-8883-8fe7be9fd0f0')
    def test_HTTPS_SIP_pool_update(self):
        self._test_pool_update(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('f269293c-b6fa-4fe2-82a6-57fc8ef89260')
    def test_PROXY_SIP_pool_update(self):
        self._test_pool_update(const.PROXY, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('f5445a86-247f-4075-8b71-e4e5415d0bed')
    def test_TCP_SIP_pool_update(self):
        self._test_pool_update(const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('d9e1aeee-21c3-4b0f-9685-834768597607')
    def test_UDP_SIP_pool_update(self):
        self._test_pool_update(const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    # Test with session persistence
    @decorators.idempotent_id('8677a512-77e1-4af3-96f7-8a3d66725e08')
    def test_HTTP_RR_app_cookie_pool_update(self):
        self._test_pool_update(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_APP_COOKIE)

    @decorators.idempotent_id('4d3b3a4a-a652-4dca-9a49-b14471ce5309')
    def test_HTTP_RR_http_cookie_pool_update(self):
        self._test_pool_update(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_HTTP_COOKIE)

    @decorators.idempotent_id('2e7bbf67-ed32-4a3c-b5ae-1aff8b07bacc')
    def test_HTTP_RR_source_IP_pool_update(self):
        self._test_pool_update(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    @decorators.idempotent_id('28b90650-a612-4b10-981f-d3dd6a366e4f')
    def test_UDP_RR_source_IP_pool_update(self):
        self._test_pool_update(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    def _test_pool_update(self, pool_protocol, algorithm,
                          session_persistence=None):
        """Tests pool update and show APIs.

        * Create a fully populated pool.
        * Show pool details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the pool.
        * Update the pool details.
        * Show pool details.
        * Validate the show reflects the updated values.
        """
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1-update")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            pool_tags = ["Hello", "World"]
            pool_kwargs.update({
                const.TAGS: pool_tags
            })

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name
            }
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_HTTP_COOKIE
            }
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_SOURCE_IP
            }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

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
        self.assertEqual(pool_protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        self.assertEmpty(pool[const.LISTENERS])
        self.assertEqual(algorithm, pool[const.LB_ALGORITHM])

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
            self.assertEqual(pool_sp_cookie_name,
                             pool[const.SESSION_PERSISTENCE][
                                 const.COOKIE_NAME])
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_HTTP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_SOURCE_IP,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])

        # Test that a user, without the loadbalancer member role, cannot
        # update this pool.
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
                'PoolClient', 'update_pool',
                expected_allowed, None, None, pool[const.ID],
                admin_state_up=True)

        # Assert we didn't go into PENDING_*
        pool_check = self.mem_pool_client.show_pool(
            pool[const.ID])
        self.assertEqual(const.ACTIVE,
                         pool_check[const.PROVISIONING_STATUS])
        self.assertFalse(pool_check[const.ADMIN_STATE_UP])

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            self.assertCountEqual(pool_kwargs[const.TAGS],
                                  pool[const.TAGS])

        new_name = data_utils.rand_name("lb_member_pool1-UPDATED")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        # We have to set it to the same protocol as not all
        # drivers support more than one pool algorithm
        pool_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.LB_ALGORITHM: algorithm,
        }

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            new_tags = ["Hola", "Mundo"]
            pool_update_kwargs.update({
                const.TAGS: new_tags
            })

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            pool_update_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_HTTP_COOKIE
            }
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            pool_update_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name
            }
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            # Some protocols only support source IP session persistence
            # so set this to the same.
            pool_update_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_SOURCE_IP
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
        self.assertEqual(algorithm, pool[const.LB_ALGORITHM])

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_HTTP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
            self.assertIsNone(
                pool[const.SESSION_PERSISTENCE].get(const.COOKIE_NAME))
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_APP_COOKIE,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
            self.assertEqual(pool_sp_cookie_name,
                             pool[const.SESSION_PERSISTENCE][
                                 const.COOKIE_NAME])
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            self.assertIsNotNone(pool.get(const.SESSION_PERSISTENCE))
            self.assertEqual(const.SESSION_PERSISTENCE_SOURCE_IP,
                             pool[const.SESSION_PERSISTENCE][const.TYPE])
            self.assertIsNone(
                pool[const.SESSION_PERSISTENCE].get(const.COOKIE_NAME))

        if self.mem_lb_client.is_version_supported(self.api_version, '2.5'):
            self.assertCountEqual(pool_update_kwargs[const.TAGS],
                                  pool[const.TAGS])

        # Also test removing a Session Persistence
        if session_persistence is not None:
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
        if session_persistence is not None:
            self.assertIsNone(pool.get(const.SESSION_PERSISTENCE))

    @decorators.idempotent_id('008088c8-696e-47ba-bc18-75827fe5956b')
    def test_HTTP_LC_pool_delete(self):
        self._test_pool_delete(const.HTTP,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('c4b2dad0-378f-4f85-a1f3-597de609b0f3')
    def test_HTTPS_LC_pool_delete(self):
        self._test_pool_delete(const.HTTPS,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('d906c63e-6090-422c-9627-e5a971e1665c')
    def test_PROXY_LC_pool_delete(self):
        self._test_pool_delete(const.PROXY,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('3bfd2d96-813b-48af-86e0-97361873a68a')
    def test_TCP_LC_pool_delete(self):
        self._test_pool_delete(const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('ea58bede-1934-480b-86fc-665b872fc946')
    def test_UDP_LC_pool_delete(self):
        self._test_pool_delete(const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('35ed3800-7a4a-47a6-9b94-c1033fff1112')
    def test_HTTP_RR_pool_delete(self):
        self._test_pool_delete(const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('c305126b-3ead-4ea8-a886-77d355c0d4a2')
    def test_HTTPS_RR_pool_delete(self):
        self._test_pool_delete(const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('729be91c-82c5-4b4e-9feb-08a1c786488b')
    def test_PROXY_RR_pool_delete(self):
        self._test_pool_delete(const.PROXY, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('a455dea2-19ce-435c-90ae-e143fe84245e')
    def test_TCP_RR_pool_delete(self):
        self._test_pool_delete(const.TCP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('63559694-6b38-4bad-9f10-3675131b28c0')
    def test_UDP_RR_pool_delete(self):
        self._test_pool_delete(const.UDP, const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('06bec76b-8fbf-4be8-9350-92590ac48606')
    def test_HTTP_SI_pool_delete(self):
        self._test_pool_delete(const.HTTP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('4b21149e-64f8-4e5f-8f71-020abbd0d0eb')
    def test_HTTPS_SI_pool_delete(self):
        self._test_pool_delete(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('277fba8f-d72b-47f0-9723-5e013f53fb7a')
    def test_PROXY_SI_pool_delete(self):
        self._test_pool_delete(const.PROXY, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('8411295f-aec0-40ab-a25d-a4677c711d98')
    def test_TCP_SI_pool_delete(self):
        self._test_pool_delete(const.TCP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('33322f21-12cc-4f2e-b406-0c11b05a1c6e')
    def test_UDP_SI_pool_delete(self):
        self._test_pool_delete(const.UDP, const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('9b40351e-1140-4b98-974c-46bd1a19763d')
    def test_HTTP_SIP_pool_delete(self):
        self._test_pool_delete(const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('391a4ed7-be97-4231-8198-5c2802bc6e30')
    def test_HTTPS_SIP_pool_delete(self):
        self._test_pool_delete(const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('1f6b6b9c-96c6-420b-bc51-8568c081a1ee')
    def test_PROXY_SIP_pool_delete(self):
        self._test_pool_delete(const.PROXY, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('fe54f133-865a-4613-9cf0-0469c780f53e')
    def test_TCP_SIP_pool_delete(self):
        self._test_pool_delete(const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('7cac0520-c7ea-49cb-8b38-0e309af2ea53')
    def test_UDP_SIP_pool_delete(self):
        self._test_pool_delete(const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)

    # Test with session persistence
    @decorators.idempotent_id('f9aa5a8c-4e2a-4029-8581-2980f1d111cf')
    def test_HTTP_RR_app_cookie_pool_delete(self):
        self._test_pool_delete(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_APP_COOKIE)

    @decorators.idempotent_id('12a31fb5-85fc-4ec8-9475-079dc06f358b')
    def test_HTTP_RR_http_cookie_pool_delete(self):
        self._test_pool_delete(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_HTTP_COOKIE)

    @decorators.idempotent_id('07528fe6-12a6-4fca-8819-9980e9d3db84')
    def test_HTTP_RR_source_IP_pool_delete(self):
        self._test_pool_delete(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    @decorators.idempotent_id('cc69c0d0-9191-4faf-a154-e33df880f44e')
    def test_UDP_RR_source_IP_pool_delete(self):
        self._test_pool_delete(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    def _test_pool_delete(self, pool_protocol, algorithm,
                          session_persistence=None):
        """Tests pool create and delete APIs.

        * Creates a pool.
        * Validates that other accounts cannot delete the pool
        * Deletes the pool.
        * Validates the pool is in the DELETED state.
        """
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1-delete")
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        if session_persistence == const.SESSION_PERSISTENCE_APP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_APP_COOKIE,
                const.COOKIE_NAME: pool_sp_cookie_name
            }
        elif session_persistence == const.SESSION_PERSISTENCE_HTTP_COOKIE:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_HTTP_COOKIE
            }
        elif session_persistence == const.SESSION_PERSISTENCE_SOURCE_IP:
            pool_kwargs[const.SESSION_PERSISTENCE] = {
                const.TYPE: const.SESSION_PERSISTENCE_SOURCE_IP
            }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the loadbalancer role cannot delete this
        # pool.
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
            self.check_delete_RBAC_enforcement(
                'PoolClient', 'delete_pool',
                expected_allowed, None, None, pool[const.ID])

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
