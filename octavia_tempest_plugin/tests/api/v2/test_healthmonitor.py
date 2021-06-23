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
from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class HealthMonitorAPITest(test_base.LoadBalancerBaseTest):
    """Test the healthmonitor object API."""
    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(HealthMonitorAPITest, cls).resource_setup()

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

    @decorators.idempotent_id('bc3fc817-3368-4e1e-bb6d-52c4de3fb10c')
    def test_LC_HTTP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('18fcd6b8-9fc3-4858-83f6-d8800052b655')
    def test_LC_HTTPS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('5b0446f2-374e-4e74-9865-72e16a19c587')
    def test_LC_PING_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('46c4e159-84d2-4876-9298-ac85561d3bd0')
    def test_LC_TCP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('a15f7319-2d3b-4ec8-9d70-e77a55045145')
    def test_LC_TLS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('f609b2c2-391d-4bc9-9793-9a4bc30ab00b')
    def test_LC_UDP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('4f20473f-ab02-4426-8d15-cf34b3c72558')
    def test_RR_HTTP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('abfff805-5491-4aef-9952-45b553cbebbb')
    def test_RR_HTTPS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('ac64228e-dc4c-4116-b610-5783a85a87f1')
    def test_RR_PING_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('e3ac7193-1dc9-41df-a4e2-7d40ca70a678')
    def test_RR_TCP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('54952a9a-b3ef-4b36-a586-9adcd63dfc49')
    def test_RR_TLS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('9af20b3c-fc42-4365-a4e9-cecbdddf90c0')
    def test_RR_UDP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('35b076a4-dfb1-4557-9eac-a33982f73856')
    def test_SI_HTTP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('965804cb-d6a1-4fdd-99dc-948829e0c046')
    def test_SI_HTTPS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('eb86eab1-4cdf-40fc-b633-679d7fb64806')
    def test_SI_PING_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('6bdab976-b6ad-4c83-87ab-0d184e80eb2c')
    def test_SI_TCP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('4f8111dd-4f03-4740-ae4b-b13b731f45a0')
    def test_SI_TLS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('d98365ca-56ba-450d-955f-d1c06c329960')
    def test_SI_UDP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('acab47f5-3006-4e84-a55f-e9dfe33113d2')
    def test_SIP_HTTP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('ca42a541-3280-4496-8604-9ce64e1992d6')
    def test_SIP_HTTPS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('78c8e5fc-3ba0-44d0-ac4a-93a90fb59c3f')
    def test_SIP_PING_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('d5b50306-a3bd-4293-96ed-17a2897d57cc')
    def test_SIP_TCP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('204556df-185e-4305-b1b7-e8d345d645e4')
    def test_SIP_TLS_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('2de53a00-c631-4985-abc1-89070ac2515f')
    def test_SIP_UDP_healthmonitor_create(self):
        self._test_healthmonitor_create(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_UDP_CONNECT)

    def _test_healthmonitor_create(self, pool_protocol, pool_algorithm,
                                   hm_type):
        """Tests healthmonitor create and basic show APIs.

        * Create a clean pool to use for the healthmonitor.
        * Tests that users without the loadbalancer member role cannot
          create healthmonitors.
        * Create a fully populated healthmonitor.
        * Show healthmonitor details.
        * Validate the show reflects the requested values.
        """
        if (pool_algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1_hm-create")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if pool_algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-create")
        delay = 3 if hm_type == const.HEALTH_MONITOR_UDP_CONNECT else 2
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.ADMIN_STATE_UP: True,
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm_kwargs.update({const.HTTP_METHOD: const.GET,
                              const.URL_PATH: '/',
                              const.EXPECTED_CODES: '200-204'})

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            hw_tags = ["Hello", "World"]
            hm_kwargs.update({
                const.TAGS: hw_tags
            })

        # Test that a user without the loadbalancer role cannot
        # create a healthmonitor
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
                'HealthMonitorClient', 'create_healthmonitor',
                expected_allowed,
                status_method=self.mem_lb_client.show_loadbalancer,
                obj_id=self.lb_id, **hm_kwargs)

        hm = self.mem_healthmonitor_client.create_healthmonitor(**hm_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

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

        # Healthmonitors are always ONLINE
        self.assertEqual(const.ONLINE, hm[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.TYPE, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.ADMIN_STATE_UP]
        if hm_type == const.HEALTH_MONITOR_HTTP:
            equal_items = equal_items + [const.HTTP_METHOD, const.URL_PATH,
                                         const.EXPECTED_CODES]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(hm_kwargs[const.TAGS], hm[const.TAGS])

    # Helper functions for test healthmonitor list
    def _filter_hms_by_pool_id(self, hms, pool_ids):
        return [hm for hm in hms
                if hm[const.POOLS][0][const.ID] in pool_ids]

    def _filter_hms_by_index(self, hms, indexes):
        return [hm for i, hm in enumerate(hms) if i not in indexes]

    @decorators.idempotent_id('9e4b1298-b6a0-46c7-b8e4-afcd31f904d3')
    def test_LC_HTTP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTP,
                                      const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                      const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('7488b1e1-12b5-4a42-9d78-9e08060ec7b1')
    def test_LC_HTTPS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTPS,
                                      const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                      const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('1f93483c-29ae-4ac1-a588-9ce9bd837232')
    def test_LC_PING_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                      const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('49ccd27c-3a4c-41e5-bcb0-d4f03ecc3e79')
    def test_LC_TCP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                      const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('60a254dc-4764-45f2-a183-8102063462e0')
    def test_LC_TLS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                      const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('6637d37d-76aa-455a-ba73-8f1a12edcedd')
    def test_LC_UDP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.UDP,
                                      const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                      const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('c9a9f20c-3680-4ae8-b657-33c687258fea')
    def test_RR_HTTP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTP,
                                      const.LB_ALGORITHM_ROUND_ROBIN,
                                      const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('93c0d03a-eb32-457b-a5af-96c03a891c06')
    def test_RR_HTTPS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTPS,
                                      const.LB_ALGORITHM_ROUND_ROBIN,
                                      const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('2ef2944f-dd56-40a5-9100-4e1b86c623af')
    def test_RR_PING_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_ROUND_ROBIN,
                                      const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('5912534f-20b3-45b7-9907-9247bf05cd13')
    def test_RR_TCP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_ROUND_ROBIN,
                                      const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('5d169fe7-16f3-4f70-8b1e-72aeeec4fd61')
    def test_RR_TLS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_ROUND_ROBIN,
                                      const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('3f81050e-4218-46fa-8d85-09807b8cdded')
    def test_RR_UDP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.UDP,
                                      const.LB_ALGORITHM_ROUND_ROBIN,
                                      const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('2df98839-7b2a-46c4-9da7-34e3d1c33851')
    def test_SI_HTTP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTP,
                                      const.LB_ALGORITHM_SOURCE_IP,
                                      const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('1ce28897-917c-4e7a-89bb-cc2aabd67037')
    def test_SI_HTTPS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTPS,
                                      const.LB_ALGORITHM_SOURCE_IP,
                                      const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('e8418eaa-73a5-4d56-8ca5-314dd2141dc9')
    def test_SI_PING_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_SOURCE_IP,
                                      const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('25203919-a039-43a4-84db-15279cbd2ec7')
    def test_SI_TCP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_SOURCE_IP,
                                      const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('4f84c05e-d4a7-4998-98cd-bc74024309f4')
    def test_SI_TLS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_SOURCE_IP,
                                      const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('4cb10c86-a875-4a9e-be8f-c0afc8aa5633')
    def test_SI_UDP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.UDP,
                                      const.LB_ALGORITHM_SOURCE_IP,
                                      const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('45bdd757-3132-4ede-8584-c46bc2f8f19e')
    def test_SIP_HTTP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTP,
                                      const.LB_ALGORITHM_SOURCE_IP_PORT,
                                      const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('300db789-b231-45be-863d-f4d6116660d3')
    def test_SIP_HTTPS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.HTTPS,
                                      const.LB_ALGORITHM_SOURCE_IP_PORT,
                                      const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('a1d534ba-ada9-4d7c-8e17-6e520a27c110')
    def test_SIP_PING_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_SOURCE_IP_PORT,
                                      const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('12c29b89-bbbc-46b0-89c5-beb42fc52181')
    def test_SIP_TCP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_SOURCE_IP_PORT,
                                      const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('a3b01b12-f4cb-4b2a-9f62-af24834ce19b')
    def test_SIP_TLS_healthmonitor_list(self):
        self._test_healthmonitor_list(const.TCP,
                                      const.LB_ALGORITHM_SOURCE_IP_PORT,
                                      const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('571e139b-08ae-4e8c-b25c-0e0bb9d198af')
    def test_SIP_UDP_healthmonitor_list(self):
        self._test_healthmonitor_list(const.UDP,
                                      const.LB_ALGORITHM_SOURCE_IP_PORT,
                                      const.HEALTH_MONITOR_UDP_CONNECT)

    def _test_healthmonitor_list(self, pool_protocol, pool_algorithm, hm_type):
        """Tests healthmonitor list API and field filtering.

        * Create three clean pools to use for the healthmonitors.
        * Create three healthmonitors.
        * Validates that other accounts cannot list the healthmonitors.
        * List the healthmonitors using the default sort order.
        * List the healthmonitors using descending sort order.
        * List the healthmonitors using ascending sort order.
        * List the healthmonitors returning one field at a time.
        * List the healthmonitors returning two fields.
        * List the healthmonitors filtering to one of the three.
        * List the healthmonitors filtered, one field, and sorted.
        """
        # IDs of health monitors created in the test
        test_ids = []

        if (pool_algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        # Get a list of pre-existing HMs to filter from test data
        pretest_hms = self.mem_healthmonitor_client.list_healthmonitors()
        # Store their IDs for easy access
        pretest_hm_ids = [hm['id'] for hm in pretest_hms]

        pool1_name = data_utils.rand_name("lb_member_pool1_hm-list")
        pool1_kwargs = {
            const.NAME: pool1_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool1 = self.mem_pool_client.create_pool(**pool1_kwargs)
        except exceptions.NotImplemented as e:
            if pool_algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        pool1_id = pool1[const.ID]
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool1_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool2_name = data_utils.rand_name("lb_member_pool2_hm-list")
        pool2_kwargs = {
            const.NAME: pool2_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool2 = self.mem_pool_client.create_pool(**pool2_kwargs)
        pool2_id = pool2[const.ID]
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool2_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool3_name = data_utils.rand_name("lb_member_pool3_hm-list")
        pool3_kwargs = {
            const.NAME: pool3_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool3 = self.mem_pool_client.create_pool(**pool3_kwargs)
        pool3_id = pool3[const.ID]
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool3_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm1_name = data_utils.rand_name("lb_member_hm2-list")
        delay = 3 if hm_type == const.HEALTH_MONITOR_UDP_CONNECT else 2
        hm1_kwargs = {
            const.POOL_ID: pool1_id,
            const.NAME: hm1_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 2,
            const.MAX_RETRIES_DOWN: 5,
            const.ADMIN_STATE_UP: True,
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm1_kwargs.update({const.HTTP_METHOD: const.GET,
                               const.URL_PATH: '/B',
                               const.EXPECTED_CODES: '200-204'})

        if self.mem_healthmonitor_client.is_version_supported(
                self.api_version, '2.5'):
            hm1_tags = ["English", "Mathematics",
                        "Marketing", "Creativity"]
            hm1_kwargs.update({const.TAGS: hm1_tags})

        hm1 = self.mem_healthmonitor_client.create_healthmonitor(
            **hm1_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm1[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        hm1 = waiters.wait_for_status(
            self.mem_healthmonitor_client.show_healthmonitor, hm1[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(hm1[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        hm2_name = data_utils.rand_name("lb_member_hm1-list")
        hm2_kwargs = {
            const.POOL_ID: pool2_id,
            const.NAME: hm2_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 1,
            const.MAX_RETRIES_DOWN: 5,
            const.ADMIN_STATE_UP: True,
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm2_kwargs.update({const.HTTP_METHOD: const.GET,
                               const.URL_PATH: '/A',
                               const.EXPECTED_CODES: '200-204'})

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            hm2_tags = ["English", "Spanish",
                        "Soft_skills", "Creativity"]
            hm2_kwargs.update({const.TAGS: hm2_tags})

        hm2 = self.mem_healthmonitor_client.create_healthmonitor(
            **hm2_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm2[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        hm2 = waiters.wait_for_status(
            self.mem_healthmonitor_client.show_healthmonitor, hm2[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(hm2[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        hm3_name = data_utils.rand_name("lb_member_hm3-list")
        hm3_kwargs = {
            const.POOL_ID: pool3_id,
            const.NAME: hm3_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 3,
            const.MAX_RETRIES_DOWN: 5,
            const.ADMIN_STATE_UP: False,
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm3_kwargs.update({const.HTTP_METHOD: const.GET,
                               const.URL_PATH: '/C',
                               const.EXPECTED_CODES: '200-204'})

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            hm3_tags = ["English", "Project_management",
                        "Communication", "Creativity"]
            hm3_kwargs.update({const.TAGS: hm3_tags})

        hm3 = self.mem_healthmonitor_client.create_healthmonitor(
            **hm3_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm3[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        hm3 = waiters.wait_for_status(
            self.mem_healthmonitor_client.show_healthmonitor, hm3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(hm3[const.ID])

        # Test that a different users cannot see the lb_member healthmonitors
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
                'HealthMonitorClient', 'list_healthmonitors',
                expected_allowed, 0)

        # Test credentials that should see these healthmonitors can see them.
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
                'HealthMonitorClient', 'list_healthmonitors',
                expected_allowed, test_ids)

        # Test that users without the lb member role cannot list healthmonitors
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
                'HealthMonitorClient', 'list_healthmonitors',
                expected_allowed)

        # Check the default sort order, created_at
        hms = self.mem_healthmonitor_client.list_healthmonitors()
        hms = self._filter_hms_by_pool_id(hms, (pool1_id, pool2_id, pool3_id))
        if hm_type == const.HEALTH_MONITOR_HTTP:
            self.assertEqual(hm1[const.URL_PATH],
                             hms[0][const.URL_PATH])
            self.assertEqual(hm2[const.URL_PATH],
                             hms[1][const.URL_PATH])
            self.assertEqual(hm3[const.URL_PATH],
                             hms[2][const.URL_PATH])
        else:
            self.assertEqual(hm1[const.MAX_RETRIES],
                             hms[0][const.MAX_RETRIES])
            self.assertEqual(hm2[const.MAX_RETRIES],
                             hms[1][const.MAX_RETRIES])
            self.assertEqual(hm3[const.MAX_RETRIES],
                             hms[2][const.MAX_RETRIES])

        # Test sort descending by description
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hms = self.mem_healthmonitor_client.list_healthmonitors(
                query_params='{sort}={url_path}:{desc}'
                             .format(sort=const.SORT,
                                     url_path=const.URL_PATH, desc=const.DESC))
            hms = self._filter_hms_by_pool_id(hms,
                                              (pool1_id, pool2_id, pool3_id))
            self.assertEqual(hm1[const.URL_PATH],
                             hms[1][const.URL_PATH])
            self.assertEqual(hm2[const.URL_PATH],
                             hms[2][const.URL_PATH])
            self.assertEqual(hm3[const.URL_PATH],
                             hms[0][const.URL_PATH])
        else:
            hms = self.mem_healthmonitor_client.list_healthmonitors(
                query_params='{sort}={url_path}:{desc}'
                             .format(sort=const.SORT,
                                     url_path=const.MAX_RETRIES,
                                     desc=const.DESC))
            hms = self._filter_hms_by_pool_id(hms,
                                              (pool1_id, pool2_id, pool3_id))
            self.assertEqual(hm1[const.MAX_RETRIES],
                             hms[1][const.MAX_RETRIES])
            self.assertEqual(hm2[const.MAX_RETRIES],
                             hms[2][const.MAX_RETRIES])
            self.assertEqual(hm3[const.MAX_RETRIES],
                             hms[0][const.MAX_RETRIES])

        # Test sort ascending by description
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hms = self.mem_healthmonitor_client.list_healthmonitors(
                query_params='{sort}={url_path}:{asc}'
                             .format(sort=const.SORT,
                                     url_path=const.URL_PATH, asc=const.ASC))
            hms = self._filter_hms_by_pool_id(hms,
                                              (pool1_id, pool2_id, pool3_id))
            self.assertEqual(hm1[const.URL_PATH],
                             hms[1][const.URL_PATH])
            self.assertEqual(hm2[const.URL_PATH],
                             hms[0][const.URL_PATH])
            self.assertEqual(hm3[const.URL_PATH],
                             hms[2][const.URL_PATH])
        else:
            hms = self.mem_healthmonitor_client.list_healthmonitors(
                query_params='{sort}={url_path}:{asc}'
                             .format(sort=const.SORT,
                                     url_path=const.MAX_RETRIES,
                                     asc=const.ASC))
            hms = self._filter_hms_by_pool_id(hms,
                                              (pool1_id, pool2_id, pool3_id))
            self.assertEqual(hm1[const.MAX_RETRIES],
                             hms[1][const.MAX_RETRIES])
            self.assertEqual(hm2[const.MAX_RETRIES],
                             hms[0][const.MAX_RETRIES])
            self.assertEqual(hm3[const.MAX_RETRIES],
                             hms[2][const.MAX_RETRIES])

        # Determine indexes of pretest HMs in default sort
        pretest_hm_indexes = []
        hms = self.mem_healthmonitor_client.list_healthmonitors()
        for i, hm in enumerate(hms):
            if hm['id'] in pretest_hm_ids:
                pretest_hm_indexes.append(i)

        # Test fields
        for field in const.SHOW_HEALTHMONITOR_RESPONSE_FIELDS:
            hms = self.mem_healthmonitor_client.list_healthmonitors(
                query_params='{fields}={field}'
                             .format(fields=const.FIELDS, field=field))
            hms = self._filter_hms_by_index(hms, pretest_hm_indexes)
            self.assertEqual(1, len(hms[0]))
            self.assertEqual(hm1[field], hms[0][field])
            self.assertEqual(hm2[field], hms[1][field])
            self.assertEqual(hm3[field], hms[2][field])

        # Test multiple fields at the same time
        hms = self.mem_healthmonitor_client.list_healthmonitors(
            query_params='{fields}={admin}&'
                         '{fields}={created}&'
                         '{fields}={pools}'.format(
                             fields=const.FIELDS,
                             admin=const.ADMIN_STATE_UP,
                             created=const.CREATED_AT,
                             pools=const.POOLS))
        hms = self._filter_hms_by_pool_id(hms, (pool1_id, pool2_id, pool3_id))
        self.assertEqual(3, len(hms[0]))
        self.assertTrue(hms[0][const.ADMIN_STATE_UP])
        parser.parse(hms[0][const.CREATED_AT])
        self.assertTrue(hms[1][const.ADMIN_STATE_UP])
        parser.parse(hms[1][const.CREATED_AT])
        self.assertFalse(hms[2][const.ADMIN_STATE_UP])
        parser.parse(hms[2][const.CREATED_AT])

        # Test filtering
        hms = self.mem_healthmonitor_client.list_healthmonitors(
            query_params='{name}={hm_name}'.format(
                name=const.NAME,
                hm_name=hm2[const.NAME]))
        self.assertEqual(1, len(hms))
        self.assertEqual(hm2[const.NAME],
                         hms[0][const.NAME])

        # Test combined params
        hms = self.mem_healthmonitor_client.list_healthmonitors(
            query_params='{admin}={true}&'
                         '{fields}={name}&{fields}={pools}&'
                         '{sort}={name}:{desc}'.format(
                             admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, name=const.NAME,
                             pools=const.POOLS, sort=const.SORT,
                             desc=const.DESC))
        hms = self._filter_hms_by_pool_id(hms, (pool1_id, pool2_id, pool3_id))
        # Should get two healthmonitors
        self.assertEqual(2, len(hms))
        # healthmonitors should have two fields
        self.assertEqual(2, len(hms[0]))
        # Should be in descending order
        self.assertEqual(hm2[const.NAME],
                         hms[1][const.NAME])
        self.assertEqual(hm1[const.NAME],
                         hms[0][const.NAME])

        # Creating a list of 3 healthmonitors, each one contains different tags
        if self.mem_healthmonitor_client.is_version_supported(
                self.api_version, '2.5'):
            list_of_hms = [hm1, hm2, hm3]
            test_list = []
            for hm in list_of_hms:

                # If tags "English" and "Creativity" are in the HM's tags
                # and "Spanish" is not, add the HM to the list
                if "English" in hm[const.TAGS] and "Creativity" in (
                    hm[const.TAGS]) and "Spanish" not in (
                        hm[const.TAGS]):
                    test_list.append(hm[const.NAME])

            # Tests if only the first and the third ones have those tags
            self.assertEqual(
                test_list, [hm1[const.NAME], hm3[const.NAME]])

            # Tests that filtering by an empty tag will return an empty list
            self.assertTrue(not any(["" in hm[const.TAGS]
                                     for hm in list_of_hms]))

    @decorators.idempotent_id('358afb0b-6259-46be-a0b3-b11e5e202624')
    def test_LC_HTTP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('c2476eea-8ae1-40ed-be55-0125f9399bd4')
    def test_LC_HTTPS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('1489251c-0704-4735-bf62-801b5277c5c9')
    def test_LC_PING_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('c761f90e-7b9c-400b-b540-e7c14f65d0a8')
    def test_LC_TCP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('8ed512d7-9fd7-4932-bf5f-090498b384bb')
    def test_LC_TLS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('a3a9be7e-83d6-42cb-b603-f14a464b8268')
    def test_LC_UDP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('284e8d3b-7b2d-4697-9e41-580b3423c0b4')
    def test_RR_HTTP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('eeb4967b-ce46-4717-a750-3e740223a804')
    def test_RR_HTTPS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('799ada1b-c082-42c5-b6ea-477f10fc88ce')
    def test_RR_PING_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('d2eae7f4-43b4-4696-93ed-a30f95c978fe')
    def test_RR_TCP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('5ce6eecc-d425-47cd-809f-aab5c56e1a9d')
    def test_RR_TLS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('a6a46e6a-a063-46bf-972c-86d0305fb766')
    def test_RR_UDP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('54d693ba-1ba4-4388-b020-c29dc3184522')
    def test_SI_HTTP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('2638718e-b345-4868-b527-9bed575e27d6')
    def test_SI_HTTPS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('124a5ca1-5eae-4ed0-8528-7a499e9ad7a2')
    def test_SI_PING_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('098ae671-1791-455a-a5a8-ada8c592a2dd')
    def test_SI_TCP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('eef8f780-b557-447f-9f61-b1f3e6daec77')
    def test_SI_TLS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('9b6d9c45-4696-4f6a-8816-594b03e3ee5b')
    def test_SI_UDP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('5653ea25-c7e0-4c72-8b2a-19dd97dd5a69')
    def test_SIP_HTTP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('fff4472d-b4de-4b8b-9748-476ffc7c8e13')
    def test_SIP_HTTPS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('1af98ebe-3f3c-4e5f-8f72-ecbd9b25c69f')
    def test_SIP_PING_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('40169a7d-84ac-4362-b8d7-64b9b807ce7e')
    def test_SIP_TCP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('15146c2e-e1c1-48ac-a7d8-3a1b4de590b2')
    def test_SIP_TLS_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('008042da-3734-4bbb-b8b2-f4ad9e2dab21')
    def test_SIP_UDP_healthmonitor_show(self):
        self._test_healthmonitor_show(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_UDP_CONNECT)

    def _test_healthmonitor_show(self, pool_protocol, pool_algorithm, hm_type):
        """Tests healthmonitor show API.

        * Create a clean pool to use for the healthmonitor.
        * Create a fully populated healthmonitor.
        * Show healthmonitor details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the healthmonitor.
        """
        if (pool_algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1_hm-show")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if pool_algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-show")
        delay = 3 if hm_type == const.HEALTH_MONITOR_UDP_CONNECT else 2
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.ADMIN_STATE_UP: True,
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm_kwargs.update({const.HTTP_METHOD: const.GET,
                              const.URL_PATH: '/',
                              const.EXPECTED_CODES: '200-204'})

        hm = self.mem_healthmonitor_client.create_healthmonitor(**hm_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

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

        # Healthmonitors are always ONLINE
        self.assertEqual(const.ONLINE, hm[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.TYPE, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.ADMIN_STATE_UP]
        if hm_type == const.HEALTH_MONITOR_HTTP:
            equal_items = equal_items + [const.HTTP_METHOD, const.URL_PATH,
                                         const.EXPECTED_CODES]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        # Test that the appropriate users can see or not see the health
        # monitors based on the API RBAC.
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
                'HealthMonitorClient', 'show_healthmonitor',
                expected_allowed, hm[const.ID])

    @decorators.idempotent_id('2417164b-ec03-4488-afd2-60b096dc0077')
    def test_LC_HTTP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('5d88aa1e-2db9-43f8-bb9b-4673c2060835')
    def test_LC_HTTPS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('61908142-9768-44aa-9a4b-b3904560a0dc')
    def test_LC_PING_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('649bdfa3-1009-4f88-bc92-c3e3141c493e')
    def test_LC_TCP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('365fffd3-0817-4907-aab1-7da60736ba60')
    def test_LC_TLS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('df29f696-a321-4626-acb2-6f66105e1661')
    def test_LC_UDP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('fa584b2c-f179-4c4e-ad2e-ff51fd1c5973')
    def test_RR_HTTP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('b927836a-2770-46ff-92de-3031c5240da6')
    def test_RR_HTTPS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('cdd559b1-5c7b-492f-9c8d-c1da6e8d7b3b')
    def test_RR_PING_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('1b9c310e-cffe-4f6a-b1af-021f751fc2a9')
    def test_RR_TCP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('4b3c9a67-f884-43a3-8f42-bac68be7060b')
    def test_RR_TLS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('805e2976-962a-4bb0-a9cc-97270a42c376')
    def test_RR_UDP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('654e4ce3-b579-4595-b1a1-6762f64b2408')
    def test_SI_HTTP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('879ef60a-4621-45aa-a520-b57da3b1fddc')
    def test_SI_HTTPS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('66e83157-53c3-4eac-a7f0-e3dc4f51de06')
    def test_SI_PING_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('ce475c4c-d01a-4cde-be71-555c84f2b8da')
    def test_SI_TCP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('b292478f-5c26-462e-b222-103be3b115d3')
    def test_SI_TLS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('49ccc552-752b-4f84-9900-65908cb13add')
    def test_SI_UDP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('d141d8d1-fa12-49cb-9d6d-413998aa2dc5')
    def test_SIP_HTTP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('9a1bbbbb-c640-48cb-bd1a-e3d3fd2602af')
    def test_SIP_HTTPS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('3f573e31-49b9-45d0-bb00-8483f48ae422')
    def test_SIP_PING_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('1a6922fd-9e8c-4836-9a6a-087f09249a49')
    def test_SIP_TCP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('e9468e81-dbff-4e88-8d4b-e2a54835c2d8')
    def test_SIP_TLS_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('64379cb2-b789-4fe6-ae3a-e62b907c6365')
    def test_SIP_UDP_healthmonitor_update(self):
        self._test_healthmonitor_update(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_UDP_CONNECT)

    def _test_healthmonitor_update(self, pool_protocol, pool_algorithm,
                                   hm_type):
        """Tests healthmonitor update and show APIs.

        * Create a clean pool to use for the healthmonitor.
        * Create a fully populated healthmonitor.
        * Show healthmonitor details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the healthmonitor.
        * Update the healthmonitor details.
        * Show healthmonitor details.
        * Validate the show reflects the updated values.
        """
        if (pool_algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1_hm-update")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if pool_algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-update")
        delay = 3 if hm_type == const.HEALTH_MONITOR_UDP_CONNECT else 2
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.ADMIN_STATE_UP: False,
        }
        if hm_type == const.HEALTH_MONITOR_HTTP:
            hm_kwargs.update({const.HTTP_METHOD: const.GET,
                              const.URL_PATH: '/',
                              const.EXPECTED_CODES: '200-204'})

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            hw_tags = ["Hello", "World"]
            hm_kwargs.update({
                const.TAGS: hw_tags
            })

        hm = self.mem_healthmonitor_client.create_healthmonitor(**hm_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

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

        # Healthmonitors are ONLINE if admin_state_up = True, else OFFLINE
        if hm_kwargs[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, hm[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, hm[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.TYPE, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.ADMIN_STATE_UP]
        if hm_type == const.HEALTH_MONITOR_HTTP:
            equal_items = equal_items + [const.HTTP_METHOD, const.URL_PATH,
                                         const.EXPECTED_CODES]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(hm_kwargs[const.TAGS], hm[const.TAGS])

        # Test that a user, without the loadbalancer member role, cannot
        # update this healthmonitor.
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
                'HealthMonitorClient', 'update_healthmonitor',
                expected_allowed, None, None, hm[const.ID],
                admin_state_up=True)

        # Assert we didn't go into PENDING_*
        hm_check = self.mem_healthmonitor_client.show_healthmonitor(
            hm[const.ID])
        self.assertEqual(const.ACTIVE,
                         hm_check[const.PROVISIONING_STATUS])
        self.assertFalse(hm_check[const.ADMIN_STATE_UP])

        new_name = data_utils.rand_name("lb_member_hm1-UPDATED")
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

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            hw_new_tags = ["Hola", "Mundo"]
            hm_update_kwargs.update({
                const.TAGS: hw_new_tags
            })

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

        # Healthmonitors are ONLINE if admin_state_up = True, else OFFLINE
        if hm_update_kwargs[const.ADMIN_STATE_UP]:
            self.assertEqual(const.ONLINE, hm[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.OFFLINE, hm[const.OPERATING_STATUS])

        # Test changed items
        equal_items = [const.NAME, const.DELAY, const.TIMEOUT,
                       const.MAX_RETRIES, const.MAX_RETRIES_DOWN,
                       const.ADMIN_STATE_UP]
        if hm_type == const.HEALTH_MONITOR_HTTP:
            equal_items = equal_items + [const.HTTP_METHOD, const.URL_PATH,
                                         const.EXPECTED_CODES]

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(hm_update_kwargs[const.TAGS], hm[const.TAGS])

        for item in equal_items:
            self.assertEqual(hm_update_kwargs[item], hm[item])

        # Test unchanged items
        equal_items = [const.TYPE]
        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

    @decorators.idempotent_id('76b3d116-0190-4de8-a58e-8e450a46a621')
    def test_LC_HTTP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('8e277e7f-49ea-4fcf-98e6-12566cc33846')
    def test_LC_HTTPS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTPS, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('c6646a25-b46d-4541-82de-75ee2beef052')
    def test_LC_PING_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('5cfacffe-63f2-4aa3-856a-9fa3dafa2d33')
    def test_LC_TCP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('a4055e48-7740-4ff5-b6e2-9e69b1d40dce')
    def test_LC_TLS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('369bd443-54ec-4071-a279-5ac1ed38c52d')
    def test_LC_UDP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.UDP, const.LB_ALGORITHM_LEAST_CONNECTIONS,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('a7bab4ac-340c-4776-ab9d-9fcb66869432')
    def test_RR_HTTP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('2991664a-9138-4c10-8e30-2cb6a82bb5b4')
    def test_RR_HTTPS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTPS, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('31f7c2c2-9174-4538-8dce-35128bc47ce7')
    def test_RR_PING_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('56e0cd28-3e74-498c-b55b-21078a758d1f')
    def test_RR_TCP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('e22a02e2-411a-46d5-9a3a-20ff37cbc835')
    def test_RR_TLS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('9221a59f-3f0f-41e8-b65c-cdbcca1a2eca')
    def test_RR_UDP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.UDP, const.LB_ALGORITHM_ROUND_ROBIN,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('717e447f-d5c8-485a-923b-da83e560273b')
    def test_SI_HTTP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('2e177a95-4ec8-4847-bd35-706b6452406a')
    def test_SI_HTTPS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('17127700-dc5f-4546-a6e6-c0b851704836')
    def test_SI_PING_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('0b1699c2-ff3e-47b6-a1ad-7128465d1233')
    def test_SI_TCP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('4ad99064-9015-40b3-8d5b-6cc99e2cc8b9')
    def test_SI_TLS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('a17825ff-e774-4230-9c53-b53bfc355d61')
    def test_SI_UDP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP,
            const.HEALTH_MONITOR_UDP_CONNECT)

    @decorators.idempotent_id('142022cc-9be3-4695-9acf-a7576e4b3268')
    def test_SIP_HTTP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTP)

    @decorators.idempotent_id('dfd994b2-511b-433f-95f7-0786f1857090')
    def test_SIP_HTTPS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.HTTPS, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_HTTPS)

    @decorators.idempotent_id('0d08ffc0-6e6a-470d-abed-5c101a828401')
    def test_SIP_PING_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_PING)

    @decorators.idempotent_id('ccf4a10c-2e72-4dbf-bc2f-134156eac3e2')
    def test_SIP_TCP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TCP)

    @decorators.idempotent_id('aaacc11e-98cd-4322-a7db-7c720eafd2b2')
    def test_SIP_TLS_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.TCP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_TLS_HELLO)

    @decorators.idempotent_id('559eccf4-eb7c-4d23-9dc8-741cc1601fc7')
    def test_SIP_UDP_healthmonitor_delete(self):
        self._test_healthmonitor_delete(
            const.UDP, const.LB_ALGORITHM_SOURCE_IP_PORT,
            const.HEALTH_MONITOR_UDP_CONNECT)

    def _test_healthmonitor_delete(self, pool_protocol, pool_algorithm,
                                   hm_type):
        """Tests healthmonitor create and delete APIs.

        * Create a clean pool to use for the healthmonitor.
        * Creates a healthmonitor.
        * Validates that other accounts cannot delete the healthmonitor
        * Deletes the healthmonitor.
        * Validates the healthmonitor is in the DELETED state.
        """
        if (pool_algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        pool_name = data_utils.rand_name("lb_member_pool1_hm-delete")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: pool_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
        }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if pool_algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-delete")
        delay = 3 if hm_type == const.HEALTH_MONITOR_UDP_CONNECT else 2
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: hm_type,
            const.DELAY: delay,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
        }
        hm = self.mem_healthmonitor_client.create_healthmonitor(**hm_kwargs)
        self.addCleanup(
            self.mem_healthmonitor_client.cleanup_healthmonitor,
            hm[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the loadbalancer role cannot delete this
        # healthmonitor.
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
                'HealthMonitorClient', 'delete_healthmonitor',
                expected_allowed, None, None, hm[const.ID])

        self.mem_healthmonitor_client.delete_healthmonitor(hm[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_healthmonitor_client.show_healthmonitor, hm[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
