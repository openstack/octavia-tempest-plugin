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
    def skip_checks(cls):
        super(HealthMonitorAPITest, cls).skip_checks()
        if not CONF.loadbalancer_feature_enabled.health_monitor_enabled:
            raise cls.skipException('Health Monitors not supported')

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
            cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

    @decorators.idempotent_id('30288670-5772-40c2-92e6-6d4a6d62d029')
    def test_healthmonitor_create(self):
        """Tests healthmonitor create and basic show APIs.

        * Create a clean pool to use for the healthmonitor.
        * Tests that users without the loadbalancer member role cannot
          create healthmonitors.
        * Create a fully populated healthmonitor.
        * Show healthmonitor details.
        * Validate the show reflects the requested values.
        """
        pool_name = data_utils.rand_name("lb_member_pool1_hm-create")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-create")
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: const.HEALTH_MONITOR_HTTP,
            const.DELAY: 2,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.HTTP_METHOD: const.GET,
            const.URL_PATH: '/',
            const.EXPECTED_CODES: '200-204',
            const.ADMIN_STATE_UP: True,
        }

        # Test that a user without the loadbalancer role cannot
        # create a healthmonitor
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.healthmonitor_client.create_healthmonitor,
                **hm_kwargs)

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
                       const.HTTP_METHOD, const.URL_PATH, const.EXPECTED_CODES,
                       const.ADMIN_STATE_UP]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

    # Helper functions for test healthmonitor list
    def _filter_hms_by_pool_id(self, hms, pool_ids):
        return [hm for hm in hms
                if hm[const.POOLS][0][const.ID] in pool_ids]

    def _filter_hms_by_index(self, hms, indexes):
        return [hm for i, hm in enumerate(hms) if i not in indexes]

    @decorators.idempotent_id('c9a9f20c-3680-4ae8-b657-33c687258fea')
    def test_healthmonitor_list(self):
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
        # Get a list of pre-existing HMs to filter from test data
        pretest_hms = self.mem_healthmonitor_client.list_healthmonitors()
        # Store their IDs for easy access
        pretest_hm_ids = [hm['id'] for hm in pretest_hms]

        pool1_name = data_utils.rand_name("lb_member_pool1_hm-list")
        pool1_kwargs = {
            const.NAME: pool1_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool1 = self.mem_pool_client.create_pool(**pool1_kwargs)
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
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
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
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
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
        hm1_kwargs = {
            const.POOL_ID: pool1_id,
            const.NAME: hm1_name,
            const.TYPE: const.HEALTH_MONITOR_HTTP,
            const.DELAY: 2,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.HTTP_METHOD: const.GET,
            const.URL_PATH: '/B',
            const.EXPECTED_CODES: '200-204',
            const.ADMIN_STATE_UP: True,
        }
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
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        hm2_name = data_utils.rand_name("lb_member_hm1-list")
        hm2_kwargs = {
            const.POOL_ID: pool2_id,
            const.NAME: hm2_name,
            const.TYPE: const.HEALTH_MONITOR_HTTP,
            const.DELAY: 2,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.HTTP_METHOD: const.GET,
            const.URL_PATH: '/A',
            const.EXPECTED_CODES: '200-204',
            const.ADMIN_STATE_UP: True,
        }
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
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        hm3_name = data_utils.rand_name("lb_member_hm3-list")
        hm3_kwargs = {
            const.POOL_ID: pool3_id,
            const.NAME: hm3_name,
            const.TYPE: const.HEALTH_MONITOR_HTTP,
            const.DELAY: 2,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.HTTP_METHOD: const.GET,
            const.URL_PATH: '/C',
            const.EXPECTED_CODES: '200-204',
            const.ADMIN_STATE_UP: False,
        }
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

        # Test that a different user cannot list healthmonitors
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.healthmonitor_client
            primary = member2_client.list_healthmonitors(
                query_params='pool_id={pool_id}'.format(pool_id=pool1_id))
            self.assertEqual(0, len(primary))

        # Test that users without the lb member role cannot list healthmonitors
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.healthmonitor_client.list_healthmonitors)

        # Check the default sort order, created_at
        hms = self.mem_healthmonitor_client.list_healthmonitors()
        hms = self._filter_hms_by_pool_id(hms, (pool1_id, pool2_id, pool3_id))
        self.assertEqual(hm1[const.URL_PATH],
                         hms[0][const.URL_PATH])
        self.assertEqual(hm2[const.URL_PATH],
                         hms[1][const.URL_PATH])
        self.assertEqual(hm3[const.URL_PATH],
                         hms[2][const.URL_PATH])

        # Test sort descending by description
        hms = self.mem_healthmonitor_client.list_healthmonitors(
            query_params='{sort}={url_path}:{desc}'
                         .format(sort=const.SORT,
                                 url_path=const.URL_PATH, desc=const.DESC))
        hms = self._filter_hms_by_pool_id(hms, (pool1_id, pool2_id, pool3_id))
        self.assertEqual(hm1[const.URL_PATH],
                         hms[1][const.URL_PATH])
        self.assertEqual(hm2[const.URL_PATH],
                         hms[2][const.URL_PATH])
        self.assertEqual(hm3[const.URL_PATH],
                         hms[0][const.URL_PATH])

        # Test sort ascending by description
        hms = self.mem_healthmonitor_client.list_healthmonitors(
            query_params='{sort}={url_path}:{asc}'
                         .format(sort=const.SORT,
                                 url_path=const.URL_PATH, asc=const.ASC))
        hms = self._filter_hms_by_pool_id(hms, (pool1_id, pool2_id, pool3_id))
        self.assertEqual(hm1[const.URL_PATH],
                         hms[1][const.URL_PATH])
        self.assertEqual(hm2[const.URL_PATH],
                         hms[0][const.URL_PATH])
        self.assertEqual(hm3[const.URL_PATH],
                         hms[2][const.URL_PATH])

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

    @decorators.idempotent_id('284e8d3b-7b2d-4697-9e41-580b3423c0b4')
    def test_healthmonitor_show(self):
        """Tests healthmonitor show API.

        * Create a clean pool to use for the healthmonitor.
        * Create a fully populated healthmonitor.
        * Show healthmonitor details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the healthmonitor.
        """
        pool_name = data_utils.rand_name("lb_member_pool1_hm-show")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-show")
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: const.HEALTH_MONITOR_HTTP,
            const.DELAY: 2,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.HTTP_METHOD: const.GET,
            const.URL_PATH: '/',
            const.EXPECTED_CODES: '200-204',
            const.ADMIN_STATE_UP: True,
        }

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
                       const.HTTP_METHOD, const.URL_PATH, const.EXPECTED_CODES,
                       const.ADMIN_STATE_UP]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        # Test that a user with lb_admin role can see the healthmonitor
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            healthmonitor_client = self.os_roles_lb_admin.healthmonitor_client
            hm_adm = healthmonitor_client.show_healthmonitor(hm[const.ID])
            self.assertEqual(hm_name, hm_adm[const.NAME])

        # Test that a user with cloud admin role can see the healthmonitor
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            adm = self.os_admin.healthmonitor_client.show_healthmonitor(
                hm[const.ID])
            self.assertEqual(hm_name, adm[const.NAME])

        # Test that a different user, with loadbalancer member role, cannot
        # see this healthmonitor
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.healthmonitor_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.show_healthmonitor,
                              hm[const.ID])

        # Test that a user, without the loadbalancer member role, cannot
        # show healthmonitors
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.healthmonitor_client.show_healthmonitor,
                hm[const.ID])

    @decorators.idempotent_id('fa584b2c-f179-4c4e-ad2e-ff51fd1c5973')
    def test_healthmonitor_update(self):
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
        pool_name = data_utils.rand_name("lb_member_pool1_hm-update")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-update")
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: const.HEALTH_MONITOR_HTTP,
            const.DELAY: 2,
            const.TIMEOUT: 3,
            const.MAX_RETRIES: 4,
            const.MAX_RETRIES_DOWN: 5,
            const.HTTP_METHOD: const.GET,
            const.URL_PATH: '/',
            const.EXPECTED_CODES: '200-204',
            const.ADMIN_STATE_UP: False,
        }

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
                       const.HTTP_METHOD, const.URL_PATH, const.EXPECTED_CODES,
                       const.ADMIN_STATE_UP]

        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

        # Test that a user, without the loadbalancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.healthmonitor_client.update_healthmonitor,
                hm[const.ID], admin_state_up=True)

        # Assert we didn't go into PENDING_*
        hm_check = self.mem_healthmonitor_client.show_healthmonitor(
            hm[const.ID])
        self.assertEqual(const.ACTIVE,
                         hm_check[const.PROVISIONING_STATUS])
        self.assertFalse(hm_check[const.ADMIN_STATE_UP])

        # Test that a user, without the loadbalancer member role, cannot
        # update this healthmonitor
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.healthmonitor_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.update_healthmonitor,
                              hm[const.ID], admin_state_up=True)

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
            const.HTTP_METHOD: const.POST,
            const.URL_PATH: '/test',
            const.EXPECTED_CODES: '201,202',
            const.ADMIN_STATE_UP: not hm_kwargs[const.ADMIN_STATE_UP],
        }
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
                       const.HTTP_METHOD, const.URL_PATH, const.EXPECTED_CODES,
                       const.ADMIN_STATE_UP]

        for item in equal_items:
            self.assertEqual(hm_update_kwargs[item], hm[item])

        # Test unchanged items
        equal_items = [const.TYPE]
        for item in equal_items:
            self.assertEqual(hm_kwargs[item], hm[item])

    @decorators.idempotent_id('a7bab4ac-340c-4776-ab9d-9fcb66869432')
    def test_healthmonitor_delete(self):
        """Tests healthmonitor create and delete APIs.

        * Create a clean pool to use for the healthmonitor.
        * Creates a healthmonitor.
        * Validates that other accounts cannot delete the healthmonitor
        * Deletes the healthmonitor.
        * Validates the healthmonitor is in the DELETED state.
        """
        pool_name = data_utils.rand_name("lb_member_pool1_hm-delete")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: self.lb_id,
        }

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-delete")
        hm_kwargs = {
            const.POOL_ID: pool[const.ID],
            const.NAME: hm_name,
            const.TYPE: const.HEALTH_MONITOR_TCP,
            const.DELAY: 2,
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

        # Test that a user without the loadbalancer role cannot
        # delete this healthmonitor
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.os_primary.healthmonitor_client.delete_healthmonitor,
                hm[const.ID])

        # Test that a different user, with the loadbalancer member role
        # cannot delete this healthmonitor
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.os_roles_lb_member2.healthmonitor_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.delete_healthmonitor,
                              hm[const.ID])

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
