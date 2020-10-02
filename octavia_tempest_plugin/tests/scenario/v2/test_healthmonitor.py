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


class HealthMonitorScenarioTest(test_base.LoadBalancerBaseTest):

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(HealthMonitorScenarioTest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_hm")
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

    @decorators.idempotent_id('4c2058f9-b8e2-4a5b-a2f3-3bd58a29f63b')
    def test_LC_HTTP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('08681eac-e907-4f71-8799-4b8fdf23914a')
    def test_LC_HTTPS_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('74611ffb-45f8-4cf5-a28c-7cc37879a27b')
    def test_LC_PING_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('cacec696-10f4-430d-bc9e-2c5f235a3324')
    def test_LC_TCP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('6becafb2-1e15-4977-bb29-b08f5728d028')
    def test_LC_TLS_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('fe43ee90-093d-4175-837e-92f803958ef1')
    def test_LC_UDP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('a51e09aa-6e44-4c67-a9e4-df70d0e08f96')
    def test_RR_HTTP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('fef9eabc-9d1e-4ad2-ae3e-05afc8c84c48')
    def test_RR_HTTPS_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('de01b73d-dba0-4426-9e20-9be3a34cfc44')
    def test_RR_PING_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('141a121a-8918-4f9c-a070-eaf8ec29008d')
    def test_RR_TCP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('de80d87a-5479-41c6-8c6b-518cc64ec62d')
    def test_RR_TLS_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('265d7359-f0a5-4083-92a8-07cb1787fe36')
    def test_RR_UDP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('20a2905f-2b53-4395-9a7f-1ded67ef4408')
    def test_SI_HTTP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('8a8cc776-b68f-4761-9bf9-cae566cdc155')
    def test_SI_HTTPS_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('296a445c-5cc8-47a7-ae26-8d548f9712c3')
    def test_SI_PING_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('94be34b1-4dc6-492b-a777-0587626a785f')
    def test_SI_TCP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('0de0e021-fd3c-4f7c-b959-67d758394fd2')
    def test_SI_TLS_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('3c79750a-aba6-4838-acbe-bc937ccf2118')
    def test_SI_UDP_healthmonitor_CRUD(self):
        self._test_healthmonitor_CRUD(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('d5e0d1b6-7cce-4592-abce-0ac6bee18818')
    def test_SIP_HTTP_healthmonitor_CRUD(self):
        try:
            self._test_healthmonitor_CRUD(
                const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT,
                const.HEALTH_MONITOR_HTTP)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @decorators.idempotent_id('e188daac-6db9-4dc2-8ecb-b47932e1984a')
    def test_SIP_HTTPS_healthmonitor_CRUD(self):
        try:
            self._test_healthmonitor_CRUD(
                const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT,
                const.HEALTH_MONITOR_HTTPS)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @decorators.idempotent_id('f9458ffd-5af7-402b-9c15-c061bf2eb9ba')
    def test_SIP_PING_healthmonitor_CRUD(self):
        try:
            self._test_healthmonitor_CRUD(
                const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
                const.HEALTH_MONITOR_PING)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @decorators.idempotent_id('b4cbe603-0a14-4778-b38c-f330053c86b6')
    def test_SIP_TCP_healthmonitor_CRUD(self):
        try:
            self._test_healthmonitor_CRUD(
                const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
                const.HEALTH_MONITOR_TCP)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @decorators.idempotent_id('57714d4c-d584-4345-9ceb-becc3ae37b7f')
    def test_SIP_TLS_healthmonitor_CRUD(self):
        try:
            self._test_healthmonitor_CRUD(
                const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
                const.HEALTH_MONITOR_TLS_HELLO)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    @decorators.idempotent_id('cc4abf84-361b-409b-b859-9a860d539deb')
    def test_SIP_UDP_healthmonitor_CRUD(self):
        try:
            self._test_healthmonitor_CRUD(
                const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT,
                const.HEALTH_MONITOR_UDP_CONNECT)
        except exceptions.NotImplemented as e:
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

    def _test_healthmonitor_CRUD(self, pool_protocol, pool_algorithm, hm_type):
        """Tests healthmonitor create, read, update, delete, and member status

        * Create a fully populated healthmonitor.
        * Show healthmonitor details.
        * Update the healthmonitor.
        * Delete the healthmonitor.
        """
        if (pool_algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1_hm")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }
        pool = self.mem_pool_client.create_pool(**pool_kwargs)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Healthmonitor create
        hm_name = data_utils.rand_name("lb_member_hm1-CRUD")
        delay = 3 if hm_type == const.HEALTH_MONITOR_UDP_CONNECT else 2
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 2,
            const.MAX_RETRIES: 2,
            const.MAX_RETRIES_DOWN: 2,
            const.ADMIN_STATE_UP: True,
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm_kwargs.update({const.HTTP_METHOD: const.GET,
                              const.URL_PATH: '/',
                              const.EXPECTED_CODES: '200'})

        hm = self.mem_healthmonitor_client.create_healthmonitor(**hm_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        hm = waiters.wait_for_status(
            self.mem_healthmonitor_client.show_healthmonitor,
            hm[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        parser.parse(hm[const.CREATED_AT])
        parser.parse(hm[const.UPDATED_AT])
        UUID(hm[const.ID])
        self.assertEqual(const.ONLINE, hm[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.TYPE, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.ADMIN_STATE_UP]
        if hm_type == const.HEALTH_MONITOR_HTTP:
            equal_items = equal_items + [const.HTTP_METHOD, const.URL_PATH,
                                         const.EXPECTED_CODES]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        # Healthmonitor update
        new_name = data_utils.rand_name("lb_member_hm1-update")
        hm_update_kwargs = {
            const.NAME: new_name,
            const.DELAY: hm_kwargs[const.DELAY] + 1,
            const.TIMEOUT: hm_kwargs[const.TIMEOUT] + 1,
            const.MAX_RETRIES: hm_kwargs[const.MAX_RETRIES] + 1,
            const.MAX_RETRIES_DOWN: hm_kwargs[const.MAX_RETRIES_DOWN] + 1,
            const.ADMIN_STATE_UP: not hm_kwargs[const.ADMIN_STATE_UP],
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm_update_kwargs.update({const.HTTP_METHOD: const.POST,
                                     const.URL_PATH: '/test',
                                     const.EXPECTED_CODES: '201,202'})

        hm = self.mem_healthmonitor_client.update_healthmonitor(
            hm[const.ID], **hm_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        hm = waiters.wait_for_status(
            self.mem_healthmonitor_client.show_healthmonitor,
            hm[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test changed items
        equal_items = [const.NAME, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.ADMIN_STATE_UP]
        if hm_type == const.HEALTH_MONITOR_HTTP:
            equal_items = equal_items + [const.HTTP_METHOD, const.URL_PATH,
                                         const.EXPECTED_CODES]

        for item in equal_items:
            self.assertEqual(hm_update_kwargs[item], hm[item])

        # Test unchanged items
        equal_items = [const.TYPE]
        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        # Healthmonitor delete
        self.mem_healthmonitor_client.delete_healthmonitor(hm[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_healthmonitor_client.show_healthmonitor, hm[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
