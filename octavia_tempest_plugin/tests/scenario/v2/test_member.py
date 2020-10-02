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
from tempest.lib.common.utils import misc
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF


# Member port numbers need to be unique on the shared pools so generate them
@misc.singleton
class MemberPort(object):

    current_port = 8000

    def increment(self):
        self.current_port += 1
        return self.current_port


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

        cls.current_listener_port = 8000
        cls.listener_pool_cache = {}
        cls.member_port = MemberPort()

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

    @classmethod
    def _listener_pool_create(cls, listener_protocol, pool_protocol,
                              algorithm):
        """Setup resources needed by the tests."""
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            cls.mem_listener_client.is_version_supported(
                cls.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')
        if (listener_protocol == const.UDP and
                not cls.mem_listener_client.is_version_supported(
                    cls.api_version, '2.1')):
            raise cls.skipException('UDP listener support is only available '
                                    'in Octavia API version 2.1 or newer')

        # Cache listener/pool combinations we have already created as
        # they can be reused for member test permutations
        listener_pool_key = listener_protocol + pool_protocol + algorithm
        pool_id = cls.listener_pool_cache.get(listener_pool_key, None)
        if pool_id is not None:
            return pool_id

        listener_name = data_utils.rand_name("lb_member_listener1_member")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: listener_protocol,
            const.PROTOCOL_PORT: cls.current_listener_port,
            const.LOADBALANCER_ID: cls.lb_id,
            # For branches that don't support multiple listeners in single
            # haproxy process and use haproxy>=1.8:
            const.CONNECTION_LIMIT: 200,
        }
        cls.current_listener_port += 1
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_member")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LISTENER_ID: listener[const.ID],
        }
        try:
            pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        cls.listener_pool_cache[listener_pool_key] = pool[const.ID]
        return pool[const.ID]

    @decorators.idempotent_id('33abafca-ce57-479e-8480-843ef412d6a6')
    def test_HTTP_LC_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('eab4eb32-b26f-4fe1-a606-1574b5b6182c')
    def test_HTTP_LC_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('80355701-bc68-4cba-a9b3-4f35fc192b6a')
    def test_HTTPS_LC_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('6f8fce94-b2aa-4497-b80f-74293d977d25')
    def test_HTTPS_LC_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('0e45c423-db43-4fee-8442-d9daabe6b2aa')
    def test_PROXY_LC_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('3ea2aad1-5650-4ec6-8394-501de33cce70')
    def test_PROXY_LC_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('9b2e7e2d-776b-419c-9717-ab4fef9cd5ca')
    def test_TCP_LC_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('06b95367-dc81-41e5-9a53-981833fb2979')
    def test_TCP_LC_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('c70bd8c6-0f6a-4ee7-840f-a3355aefd471')
    def test_UDP_LC_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('0b4ec248-c6a0-4d29-b77e-189453ec0535')
    def test_UDP_LC_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('15c8c3e3-569c-4029-95df-a9f72049e267')
    def test_HTTP_RR_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('a0f02494-ffb3-47be-8670-f56c0df9ec94')
    def test_HTTP_RR_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('57aee0db-3295-42b7-a7d3-aae942a6cb41')
    def test_HTTPS_RR_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('6c3e5bd7-4573-4f6d-ac64-31b238c9ea51')
    def test_HTTPS_RR_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('e0ad1fa0-1fdb-472d-9d69-8968631c9239')
    def test_PROXY_RR_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('534fbc38-1c70-4c67-8f89-74a6905b1c98')
    def test_PROXY_RR_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('c4c72e4b-5abe-41df-9f1d-6a8a27c75a80')
    def test_TCP_RR_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('673425e0-2a57-4c92-a416-7b4e0824708f')
    def test_TCP_RR_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('f08c9efc-b69c-4c0f-a731-74ec8c17fc91')
    def test_UDP_RR_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('94829e1e-506e-4f3c-ab04-4e338787ccfd')
    def test_UDP_RR_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('07d1e571-d12c-4e04-90d1-8f4f42610df3')
    def test_HTTP_SI_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('3910a7ec-63c5-4152-9fe1-ce21d3e1cdca')
    def test_HTTP_SI_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('32b0b541-29dc-464b-91c1-115413539de7')
    def test_HTTPS_SI_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('d59ea523-8dac-4e19-8df4-a7076a17296c')
    def test_HTTPS_SI_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('12348506-1cfc-4d62-9cc2-d380776a9154')
    def test_PROXY_SI_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('5d3879a6-d103-4800-bca4-1ef18ecbee68')
    def test_PROXY_SI_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('efb158e2-de75-4d8b-8566-a0fa5fd75173')
    def test_TCP_SI_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('4f1661e5-1dff-4910-9ecd-96327ea3e873')
    def test_TCP_SI_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('0984583b-daaf-4509-bf1f-ff3acf33836b')
    def test_UDP_SI_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('16b84495-e8f8-4e7b-b242-43a6e00fb8ad')
    def test_UDP_SI_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('ab8f46fe-0c84-4755-a9a2-80cc1fbdea18')
    def test_HTTP_SIP_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('7470bea5-9ea0-4e04-a82f-a0bed202b97d')
    def test_HTTP_SIP_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('e59e9a7d-b6e7-43e9-b9d5-0717f113d769')
    def test_HTTPS_SIP_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('761e1acd-3f4c-4e02-89e1-f89adfe2e3f9')
    def test_HTTPS_SIP_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('ba7b0c73-df44-4a1a-a610-a107daabc36d')
    def test_PROXY_SIP_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('ad43bc3f-2664-42c4-999f-9763facb8d15')
    def test_PROXY_SIP_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('3341d05c-c199-496f-ac40-6248818ce831')
    def test_TCP_SIP_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('5872f1de-1a33-4c20-bc02-7d058e3c3b55')
    def test_TCP_SIP_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    @decorators.idempotent_id('9550835b-c9ef-44e3-8087-151c25a95168')
    def test_UDP_SIP_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id)

    @decorators.idempotent_id('5f40b080-0f2c-4791-a509-da7cfe9eace4')
    def test_UDP_SIP_alt_monitor_member_crud(self):
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_CRUD(pool_id, alternate_monitoring=True)

    def _test_member_CRUD(self, pool_id, alternate_monitoring=False):
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
            const.POOL_ID: pool_id,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 80,
            const.WEIGHT: 50,
        }
        if alternate_monitoring:
            member_kwargs[const.MONITOR_ADDRESS] = '192.0.2.2'
            member_kwargs[const.MONITOR_PORT] = 8080

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_kwargs.update({
                const.BACKUP: False,
            })

        if self.lb_member_vip_subnet:
            member_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        member = self.mem_member_client.create_member(**member_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member[const.ID], pool_id=pool_id,
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
            pool_id=pool_id)

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
            pool_id=pool_id)

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]
        if alternate_monitoring:
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

        if alternate_monitoring:
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
            pool_id=pool_id)

        # Test changed items
        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.WEIGHT]
        if alternate_monitoring:
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
            pool_id=pool_id)

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_member_client.show_member, member[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout,
            pool_id=pool_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

    def _test_mixed_member_create(self, pool_id):
        member_name = data_utils.rand_name("lb_member_member1-create")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: pool_id,
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
            member[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

    @decorators.idempotent_id('f9bc8ef1-cf21-41e5-819d-7561173e5286')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTP_LC_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('e63c89a7-30a3-4eff-8ff5-dd62a5ecec0f')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTPS_LC_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('efaa9ed0-c261-4184-9693-0020965606a8')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_PROXY_LC_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('f4ac056c-2cb8-457f-b1b1-9b49226f9b9f')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_TCP_LC_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('90e22b80-d52b-4af2-9c4d-9be44eed9575')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_mixed_UDP_LC_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('b8afb91d-9b85-4569-85c7-03453df8990b')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTP_RR_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('a64dc345-4afe-4a2c-8a6a-178dd5a94670')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTPS_RR_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('909aebf2-f9e4-4b96-943e-c02b8a415cd2')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_PROXY_RR_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('407ff3d4-f0a2-4d27-be69-3f2ec039a6a0')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_TCP_RR_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('e74b28cf-ab1a-423b-a1c5-d940e3c0a5ab')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_mixed_UDP_RR_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('cc7f9272-84a6-436c-a529-171b67a45b62')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTP_SI_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('704a10ed-d52d-4c75-9445-9ef98f7f540f')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTPS_SI_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_SOURCE_IP)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('4c516b5b-eb7b-4a4c-9a73-fba823332e25')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_PROXY_SI_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_SOURCE_IP)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('61973bc8-8bc4-4aec-bf57-b37583887544')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_TCP_SI_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('ddab1836-ba9f-42e5-9630-1572d4a63501')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_mixed_UDP_SI_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_SOURCE_IP)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('b3dc557a-88ec-4bc6-84fd-c3aaab5d5920')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTP_SIP_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTP, const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('d6f3908d-470a-4939-b407-c6d6324c06b6')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_HTTPS_SIP_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.HTTPS, const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('ab745620-bf92-49e1-ac35-e42f266a7612')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_PROXY_SIP_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.PROXY, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('c7ffbd6e-5d9f-45e8-a5d0-2d26ea6b0ed0')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    def test_mixed_TCP_SIP_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        pool_id = self._listener_pool_create(
            const.TCP, const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_mixed_member_create(pool_id)

    @decorators.idempotent_id('aa6b282c-d1c2-4a39-b085-33c224d4faff')
    @testtools.skipUnless(CONF.load_balancer.test_with_ipv6,
                          'IPv6 testing is disabled')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=CONF.load_balancer.provider in const.AMPHORA_PROVIDERS)
    def test_mixed_UDP_SIP_member_create(self):
        """Test the member creation with mixed IP protocol members/VIP."""
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            raise self.skipException('UDP listener support is only available '
                                     'in Octavia API version 2.1 or newer')
        pool_id = self._listener_pool_create(
            const.UDP, const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_mixed_member_create(pool_id)
