# Copyright 2018 GoDaddy
# Copyright 2018 Rackspace US Inc.  All rights reserved.
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

import requests
import testtools
import time

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


@testtools.skipUnless(
    CONF.validation.run_validation,
    'Active-Standby tests will not work without run_validation enabled.')
class ActiveStandbyScenarioTest(test_base.LoadBalancerBaseTestWithCompute):

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(ActiveStandbyScenarioTest, cls).resource_setup()

        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not cls.lb_admin_flavor_profile_client.is_version_supported(
                cls.api_version, '2.3'):
            return

        lb_name = data_utils.rand_name("lb_member_lb1_actstdby")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        # TODO(rm_work): Make this work with ipv6 and split this test for both
        ip_version = 4
        cls._setup_lb_network_kwargs(lb_kwargs, ip_version)

        lb = cls.mem_lb_client.create_loadbalancer(**lb_kwargs)
        cls.lb_id = lb[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_lb_client.cleanup_loadbalancer,
            cls.lb_id)

        if CONF.validation.connect_method == 'floating':
            port_id = lb[const.VIP_PORT_ID]
            result = cls.lb_mem_float_ip_client.create_floatingip(
                floating_network_id=CONF.network.public_network_id,
                port_id=port_id)
            floating_ip = result['floatingip']
            LOG.info('lb1_floating_ip: {}'.format(floating_ip))
            cls.addClassResourceCleanup(
                waiters.wait_for_not_found,
                cls.lb_mem_float_ip_client.delete_floatingip,
                cls.lb_mem_float_ip_client.show_floatingip,
                floatingip_id=floating_ip['id'])
            cls.lb_vip_address = floating_ip['floating_ip_address']
        else:
            cls.lb_vip_address = lb[const.VIP_ADDRESS]

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        listener_name = data_utils.rand_name("lb_member_listener1_actstdby")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '80',
            const.LOADBALANCER_ID: cls.lb_id,
        }
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)
        cls.listener_id = listener[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_listener_client.cleanup_listener,
            cls.listener_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_actstdby")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LISTENER_ID: cls.listener_id,
        }
        pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        cls.pool_id = pool[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_pool_client.cleanup_pool,
            cls.pool_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1_actstdby")
        member1_kwargs = {
            const.POOL_ID: cls.pool_id,
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: cls.webserver1_ip,
            const.PROTOCOL_PORT: 80,
        }
        if cls.lb_member_1_subnet:
            member1_kwargs[const.SUBNET_ID] = cls.lb_member_1_subnet[const.ID]

        member1 = cls.mem_member_client.create_member(
            **member1_kwargs)
        cls.addClassResourceCleanup(
            cls.mem_member_client.cleanup_member,
            member1[const.ID], pool_id=cls.pool_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)
        waiters.wait_for_status(
            cls.mem_lb_client.show_loadbalancer, cls.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2_actstdby")
        member2_kwargs = {
            const.POOL_ID: cls.pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: cls.webserver2_ip,
            const.PROTOCOL_PORT: 80,
        }
        if cls.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = cls.lb_member_2_subnet[const.ID]

        member2 = cls.mem_member_client.create_member(
            **member2_kwargs)
        cls.addClassResourceCleanup(
            cls.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=cls.pool_id,
            lb_client=cls.mem_lb_client, lb_id=cls.lb_id)
        waiters.wait_for_status(
            cls.mem_lb_client.show_loadbalancer, cls.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Active/Standby tests will not work in noop mode.')
    @decorators.idempotent_id('e591fa7a-0eee-485a-8ca0-5cf1a556bdf0')
    def test_active_standby_vrrp_failover(self):
        """Tests active/standby VRRP failover

        * Test the load balancer to make sure it is functioning
        * Identifies the Master and Backup amphora
        * Deletes the Master amphora
        * Sends traffic through the load balancer
        * Validates that the Backup has assumed the Master role
        """
        amphora_client = self.os_admin.load_balancer_v2.AmphoraClient()
        # We have to do this here as the api_version and clients are not
        # setup in time to use a decorator or the skip_checks mixin
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.4'):
            raise self.skipException(
                'Active/Standby VRRP failover tests require '
                'Octavia API version 2.3 or newer.')

        session = requests.Session()

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address)

        # Get the amphorae associated with this load balancer
        amphorae = amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID,
                lb_id=self.lb_id))

        # TODO(johnsom): Fix when LB flavors support act/stdby
        if len(amphorae) < 2:
            self.skipTest('Load balancer must be using active/standby '
                          'topology for the VRRP failover test.')

        # Generate traffic on the LB so we can identify the current Master
        r = session.get('http://{0}'.format(self.lb_vip_address), timeout=2)

        # Cycle through the amps to find the master
        master_amp = None
        backup_amp = None
        start = int(time.time())
        while True:
            for amp in amphorae:
                amphora_stats = amphora_client.get_amphora_stats(
                    amp[const.ID])
                for listener in amphora_stats:
                    if listener[const.TOTAL_CONNECTIONS] > 0:
                        master_amp = amp
                        break
                # check if we left the listener for loop by finding the master
                if master_amp:
                    break
            # If we found the master and broke out of the amp for loop, break
            # out of the while loop too.
            if master_amp:
                break
            if int(time.time()) - start >= CONF.load_balancer.check_timeout:
                message = ('Unable to find Master amphora in {timeout} '
                           'seconds.'.format(
                               timeout=CONF.load_balancer.check_timeout))
                raise exceptions.TimeoutException(message)
            time.sleep(CONF.load_balancer.check_interval)

        # Find the backup amphora and check it is ready for the test
        for amp in amphorae:
            if amp[const.ID] == master_amp[const.ID]:
                continue
            else:
                backup_amp = amp
        self.assertIsNotNone(backup_amp)
        amphora_stats = amphora_client.get_amphora_stats(
            backup_amp[const.ID])
        for listener in amphora_stats:
            self.assertEqual(0, listener[const.TOTAL_CONNECTIONS])

        # Delete the master amphora compute instance
        self.os_admin_servers_client.delete_server(
            master_amp[const.COMPUTE_ID])

        # Pass some traffic through the LB
        # Note: We want this to loop for longer than the heartbeat interval
        #       to make sure a stats update has come in to the HM
        for x in range(0, 20):
            try:
                r = session.get('http://{0}'.format(self.lb_vip_address),
                                timeout=1)
                LOG.info('Got response: %s', r.text)
            except Exception:
                LOG.info('Load balancer request failed. Looping')
            time.sleep(1)

        # Check that the Backup amphora is now Master
        amphora_stats = amphora_client.get_amphora_stats(
            backup_amp[const.ID])
        connections = 0
        for listener in amphora_stats:
            connections += listener[const.TOTAL_CONNECTIONS]
        self.assertGreater(connections, 0)
        LOG.info('Backup amphora is now Master.')
        # Wait for the amphora failover to start
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.PENDING_UPDATE, CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        # Wait for the load balancer to return to ACTIVE so the
        # cleanup steps will pass
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE, CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)
