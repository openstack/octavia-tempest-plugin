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
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


class PoolScenarioTest(test_base.LoadBalancerBaseTest):

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(PoolScenarioTest, cls).resource_setup()

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
    @decorators.idempotent_id('f30bd185-ca13-45c1-8a2f-f4179e7f0c3a')
    def test_HTTP_LC_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTP, protocol_port=10,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('d8c428b0-dee4-4374-8286-31e52aeb7fe5')
    def test_HTTP_LC_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTP,
                             pool_protocol=const.HTTP, protocol_port=11,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('82d8e035-4068-4bad-a87b-e4907bf6d464')
    def test_HTTPS_LC_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTPS, protocol_port=12,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('726beb03-de8c-43cd-ba5f-e7d6faf627a3')
    def test_HTTPS_LC_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTPS,
                             pool_protocol=const.HTTPS, protocol_port=13,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('b3cef24e-343a-4e77-833b-422158d54673')
    def test_PROXY_LC_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.PROXY, protocol_port=14,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('f1edfb45-a9d3-4150-8bc9-4fc3427c6346')
    def test_PROXY_LC_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.PROXY, protocol_port=15,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('d6d067c3-ec63-4b5d-a364-acc7493ae3b8')
    def test_TCP_LC_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.TCP, protocol_port=16,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('a159c345-9463-4c01-b571-086c789bd7d5')
    def test_TCP_LC_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.TCP, protocol_port=17,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('6fea6a39-19eb-4a0e-b507-82ecc57c1dc5')
    def test_UDP_LC_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.UDP, protocol_port=18,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('6ce12d8c-ad59-4e48-8de1-d26926735457')
    def test_UDP_LC_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.UDP,
                             pool_protocol=const.UDP, protocol_port=19,
                             algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)

    # Pool with Round Robin algorithm
    @decorators.idempotent_id('dfa120bf-81b9-4f22-bb5e-7df660c18173')
    def test_HTTP_RR_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTP, protocol_port=20,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('087da8ab-79c7-48ba-871c-5769185cea3e')
    def test_HTTP_RR_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTP,
                             pool_protocol=const.HTTP, protocol_port=21,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('6179a5d1-6425-4144-a437-b0d260b7b883')
    def test_HTTPS_RR_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTPS, protocol_port=22,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('1b4585b4-c521-48e8-a69a-8a1d729a2949')
    def test_HTTPS_RR_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTPS,
                             pool_protocol=const.HTTPS, protocol_port=23,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('6b9f4f01-cb78-409a-b9fe-cbbeb27d0c5f')
    def test_PROXY_RR_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.PROXY, protocol_port=24,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('0228ea63-dff5-4dfb-b48a-193e8509caa8')
    def test_PROXY_RR_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.PROXY, protocol_port=25,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('71088923-cfdf-4821-a6a8-c7c9045b624d')
    def test_TCP_RR_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.TCP, protocol_port=26,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('4b663772-5c6b-49a3-b592-49d91bd71ff1')
    def test_TCP_RR_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.TCP, protocol_port=27,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('45aefaa0-c909-4861-91c6-517ea10285a5')
    def test_UDP_RR_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.UDP, protocol_port=28,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('cff21560-52be-439f-a41f-789d365db567')
    def test_UDP_RR_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.UDP,
                             pool_protocol=const.UDP, protocol_port=29,
                             algorithm=const.LB_ALGORITHM_ROUND_ROBIN)

    # Pool with Source IP algorithm
    @decorators.idempotent_id('4ef47185-ef22-4396-8c9c-b98b9b476605')
    def test_HTTP_SI_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTP, protocol_port=30,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('13a5caba-42a5-4b8c-a389-74d630a91687')
    def test_HTTP_SI_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTP,
                             pool_protocol=const.HTTP, protocol_port=31,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('5ff7732a-7481-4c03-8efc-5ee794feb11a')
    def test_HTTPS_SI_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTPS, protocol_port=32,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('30f3d93c-cc22-4821-8805-d5c41023eccd')
    def test_HTTPS_SI_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTPS,
                             pool_protocol=const.HTTPS, protocol_port=33,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('7cbb01b8-196b-4ac3-9fec-a41abf867850')
    def test_PROXY_SI_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.PROXY, protocol_port=34,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('29327103-4949-4a77-a748-87ab725237b7')
    def test_PROXY_SI_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.PROXY, protocol_port=35,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('6a4dd425-d7d9-40dd-b451-feb4b3c551cc')
    def test_TCP_SI_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.TCP, protocol_port=36,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('4391d6a5-bb1c-4ff0-9f74-7b8c43a0b150')
    def test_TCP_SI_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.TCP, protocol_port=37,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('211a688c-f495-4f32-a297-c64d240b5de0')
    def test_UDP_SI_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.UDP, protocol_port=38,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('b19f1285-dbf2-4ac9-9199-3c3693148133')
    def test_UDP_SI_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.UDP,
                             pool_protocol=const.UDP, protocol_port=39,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP)

    # Pool with Source IP Port algorithm
    @decorators.idempotent_id('fee61d34-e272-42f5-92e2-69b515c6cded')
    def test_HTTP_SIP_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTP, protocol_port=40,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('d99948da-649d-493c-a74d-72e532df0605')
    def test_HTTP_SIP_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTP,
                             pool_protocol=const.HTTP, protocol_port=41,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('b3c68f89-634e-4279-9546-9f2d2eac4bfa')
    def test_HTTPS_SIP_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.HTTPS, protocol_port=42,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('4327f636-50c3-411c-b90e-0b907bdaffc5')
    def test_HTTPS_SIP_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.HTTPS,
                             pool_protocol=const.HTTPS, protocol_port=43,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('95a93e91-6ac0-40d5-999c-84a8b68c14f4')
    def test_PROXY_SIP_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.PROXY, protocol_port=44,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('13893ac9-150f-4605-be68-6bdf65e2bb12')
    def test_PROXY_SIP_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.PROXY, protocol_port=45,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('d045ea39-b6dd-4171-bb90-2b9970e25303')
    def test_TCP_SIP_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.TCP, protocol_port=46,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('ec22ab54-8e0a-4472-8f70-78c34f28dc36')
    def test_TCP_SIP_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.TCP,
                             pool_protocol=const.TCP, protocol_port=47,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('0e0f0299-8c5e-4d7c-a99e-85db43b45446')
    def test_UDP_SIP_pool_standalone_CRUD(self):
        self._test_pool_CRUD(listener_protocol=None,
                             pool_protocol=const.UDP, protocol_port=48,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('66d50010-13ca-4588-ae36-61bb783d556e')
    def test_UDP_SIP_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(listener_protocol=const.UDP,
                             pool_protocol=const.UDP, protocol_port=49,
                             algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)

    # Test with session persistence
    @decorators.idempotent_id('d6b8119b-40e9-487d-a037-9972a1e688e8')
    def test_HTTP_RR_app_cookie_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(
            listener_protocol=const.HTTP,
            pool_protocol=const.HTTP, protocol_port=50,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_APP_COOKIE)

    @decorators.idempotent_id('a67f2276-6469-48d4-bf7e-ddf6d8694dba')
    def test_HTTP_RR_http_cookie_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(
            listener_protocol=const.HTTP,
            pool_protocol=const.HTTP, protocol_port=51,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_HTTP_COOKIE)

    @decorators.idempotent_id('c248e3d8-43d9-4fd4-93af-845747c9b939')
    def test_HTTP_RR_source_IP_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(
            listener_protocol=const.HTTP,
            pool_protocol=const.HTTP, protocol_port=52,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    @decorators.idempotent_id('dc7f0ed5-f94c-4498-9dca-5dbc08e7162f')
    def test_UDP_RR_source_ip_pool_with_listener_CRUD(self):
        self._test_pool_CRUD(
            listener_protocol=const.UDP,
            pool_protocol=const.UDP, protocol_port=53,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN,
            session_persistence=const.SESSION_PERSISTENCE_SOURCE_IP)

    def _test_pool_CRUD(self, listener_protocol, pool_protocol, protocol_port,
                        algorithm, session_persistence=None):
        """Tests pool create, read, update, delete

        * Create a fully populated pool.
        * Show pool details.
        * Update the pool.
        * Delete the pool.
        """
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        # Listener create
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
            listener_id = listener[const.ID]

            waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                    self.lb_id, const.PROVISIONING_STATUS,
                                    const.ACTIVE,
                                    CONF.load_balancer.build_interval,
                                    CONF.load_balancer.build_timeout)

        # Pool create
        pool_name = data_utils.rand_name("lb_member_pool1-CRUD")
        pool_description = data_utils.arbitrary_string(size=255)
        pool_sp_cookie_name = 'my_cookie'
        pool_kwargs = {
            const.NAME: pool_name,
            const.DESCRIPTION: pool_description,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
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

        if listener_protocol is not None:
            pool_kwargs[const.LISTENER_ID] = listener_id
        else:
            pool_kwargs[const.LOADBALANCER_ID] = self.lb_id

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

        self.addCleanup(
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
        self.assertEqual(pool_protocol, pool[const.PROTOCOL])
        self.assertEqual(1, len(pool[const.LOADBALANCERS]))
        self.assertEqual(self.lb_id, pool[const.LOADBALANCERS][0][const.ID])
        if listener_protocol is not None:
            self.assertEqual(1, len(pool[const.LISTENERS]))
            self.assertEqual(listener_id, pool[const.LISTENERS][0][const.ID])
        else:
            self.assertEmpty(pool[const.LISTENERS])
            self.assertEqual(const.OFFLINE, pool[const.OPERATING_STATUS])
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

        # Pool update
        new_name = data_utils.rand_name("lb_member_pool1-update")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        pool_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
        }

        # We have to set it to the same protocol as not all
        # drivers support more than one pool algorithm
        pool_update_kwargs[const.LB_ALGORITHM] = algorithm

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
        if listener_protocol is not None:
            pool = waiters.wait_for_status(
                self.mem_pool_client.show_pool,
                pool[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

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

        # Pool delete
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

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
