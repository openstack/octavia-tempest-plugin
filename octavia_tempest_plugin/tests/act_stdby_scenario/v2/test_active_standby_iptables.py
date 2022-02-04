# Copyright 2019 Rackspace US Inc.  All rights reserved.
# Copyright 2019 Red Hat Inc.  All rights reserved.
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

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.linux import remote_client
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
class ActiveStandbyIptablesScenarioTest(
        test_base.LoadBalancerBaseTestWithCompute):

    @classmethod
    def skip_checks(cls):
        super(ActiveStandbyIptablesScenarioTest, cls).skip_checks()

        if CONF.load_balancer.provider not in ['amphora', 'octavia']:
            raise cls.skipException("Amphora tests require provider 'amphora' "
                                    "or 'octavia' (alias to 'amphora', "
                                    "deprecated) set.")

        if CONF.load_balancer.loadbalancer_topology != const.ACTIVE_STANDBY:
            raise cls.skipException("Configured load balancer topology is not "
                                    "%s." % const.ACTIVE_STANDBY)

        cls._get_amphora_ssh_key()

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(ActiveStandbyIptablesScenarioTest, cls).resource_setup()

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
            const.LB_ALGORITHM: cls.lb_algorithm,
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

    @classmethod
    def _log_vip_traffic(cls, amp, log_prefix):
        ssh_key = cls._get_amphora_ssh_key()
        linux_client = remote_client.RemoteClient(
            amp['lb_network_ip'], CONF.load_balancer.amphora_ssh_user,
            pkey=ssh_key,
            **cls.remote_client_args())
        linux_client.validate_authentication()

        # Allow logging from non-init namespaces
        # https://lore.kernel.org/patchwork/patch/673714/
        linux_client.exec_command('echo 1 | sudo tee '
                                  '/proc/sys/net/netfilter/nf_log_all_netns')

        linux_client.exec_command('sudo ip netns exec amphora-haproxy '
                                  'iptables -I INPUT 1 -d {0} -j LOG '
                                  '--log-prefix "{1}"'
                                  .format(amp['ha_ip'], log_prefix))

    @classmethod
    def _has_vip_traffic(cls, ip_address, log_prefix):
        ssh_key = cls._get_amphora_ssh_key()
        linux_client = remote_client.RemoteClient(
            ip_address, CONF.load_balancer.amphora_ssh_user, pkey=ssh_key,
            **cls.remote_client_args())
        linux_client.validate_authentication()

        try:
            linux_client.exec_command('sudo journalctl -t kernel | grep {0}'
                                      .format(log_prefix))
            return True
        except exceptions.SSHExecCommandFailed:
            return False

    @classmethod
    def _get_active_standby_amps(cls, amps, log_prefix):
        active = None
        stby = None
        for amp in amps:
            if cls._has_vip_traffic(amp['lb_network_ip'], log_prefix):
                if active:
                    LOG.exception('Failed to determine single active amphora.')
                    raise Exception('More than one amphora is forwarding VIP '
                                    'traffic.')
                active = amp
            else:
                stby = amp

        return active, stby

    @classmethod
    def _get_amphora_ssh_key(cls):
        key_file = CONF.load_balancer.amphora_ssh_key
        try:
            with open(key_file, 'r') as f:
                return f.read()
        except IOError:
            raise Exception("Could not open amphora SSH key file {0}."
                            .format(key_file))

    @testtools.skipIf(CONF.load_balancer.test_with_noop,
                      'Active/Standby tests will not work in noop mode.')
    @decorators.idempotent_id('deab2b3f-62c7-4a05-9e92-aa45a04773fd')
    def test_active_standby_vrrp_failover(self):
        """Tests active/standby VRRP failover

        * Test the load balancer to make sure it is functioning
        * Identifies the Master and Backup amphora
        * Deletes the Master amphora
        * Sends traffic through the load balancer
        * Validates that the Backup has assumed the Master role
        """

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address)

        # Check there are two amphorae associated to the load balancer
        amps = self.os_admin.amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))
        self.assertEqual(2, len(amps))

        # Log VIP traffic
        for amp in amps:
            self._log_vip_traffic(amp, 'ACTSTBY-1')

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address)

        # Which amphora is the active?
        active = self._get_active_standby_amps(amps, 'ACTSTBY-1')[0]

        # Delete active amphora
        self.os_admin_servers_client.delete_server(active[const.COMPUTE_ID])

        # Wait for the amphora failover to start
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.PENDING_UPDATE, CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Send some traffic (checks VRRP failover)
        self.check_members_balanced(self.lb_vip_address)

        # Wait for the load balancer to return to ACTIVE
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE, CONF.load_balancer.lb_build_interval,
            CONF.load_balancer.lb_build_timeout)

        # Check again there are two amphorae associated to the load balancer
        amps = self.os_admin.amphora_client.list_amphorae(
            query_params='{loadbalancer_id}={lb_id}'.format(
                loadbalancer_id=const.LOADBALANCER_ID, lb_id=self.lb_id))
        self.assertEqual(2, len(amps))

        # Log VIP traffic
        for amp in amps:
            self._log_vip_traffic(amp, 'ACTSTBY-2')

        # Send some traffic
        self.check_members_balanced(self.lb_vip_address)

        # Ensure only one amphora is handling VIP traffic
        self._get_active_standby_amps(amps, 'ACTSTBY-2')
