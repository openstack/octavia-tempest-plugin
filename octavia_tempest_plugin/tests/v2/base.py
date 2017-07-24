# Copyright 2017 GoDaddy
# Copyright 2017 Catalyst IT Ltd
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
import time

from oslo_log import log as logging
import requests
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest import test
import tenacity

from octavia_tempest_plugin.tests import server_util

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BaseLoadbalancerTest(test.BaseTestCase):
    credentials = (['lbmember', CONF.loadbalancer.member_role], 'admin')
    name_prefix = 'Tempest-BaseLoadbalancerTest'
    vip_network_id = None
    vip_subnet_id = None
    vip_address = None
    member_subnet_id = None
    member_network_id = None
    vm_ip = None

    @classmethod
    def skip_checks(cls):
        super(BaseLoadbalancerTest, cls).skip_checks()

        if not CONF.service_available.loadbalancer:
            raise cls.skipException("Loadbalancing service is not available.")

        service_list = {
            'loadbalancing': CONF.service_available.loadbalancer,
            'compute': CONF.service_available.nova,
            'image': CONF.service_available.glance,
            'neutron': CONF.service_available.neutron
        }
        for srv, available in service_list.items():
            if not available:
                raise cls.skipException("Service %s is not available." % srv)

    @classmethod
    def setup_clients(cls):
        super(BaseLoadbalancerTest, cls).setup_clients()

        cls.lb_client = cls.os_roles_lbmember.octavia_v2.LoadbalancerClient()
        cls.servers_client = cls.os_roles_lbmember.servers_client
        cls.networks_client = cls.os_roles_lbmember.networks_client
        cls.subnets_client = cls.os_roles_lbmember.subnets_client
        cls.interfaces_client = cls.os_roles_lbmember.interfaces_client
        cls.sg_rule_client = cls.os_roles_lbmember.security_group_rules_client
        cls.floatingip_client = cls.os_roles_lbmember.floating_ips_client
        cls.floatingip_adm_client = cls.os_admin.floating_ips_client
        cls.routers_adm_client = cls.os_admin.routers_client

        if CONF.identity.auth_version == 'v3':
            project_id = cls.os_roles_lbmember.auth_provider.auth_data[1][
                'project']['id']
        else:
            project_id = cls.os_roles_lbmember.auth_provider.auth_data[
                1]['token']['tenant']['id']

        cls.tenant_id = project_id
        cls.user_id = cls.os_roles_lbmember.auth_provider.auth_data[1][
            'user']['id']

    @classmethod
    def resource_setup(cls):
        """Creates network resources."""
        super(BaseLoadbalancerTest, cls).resource_setup()
        if not CONF.loadbalancer.vip_network_id:
            network_name = data_utils.rand_name(
                'network',
                prefix=cls.name_prefix
            )
            body = cls.networks_client.create_network(name=network_name)
            cls.vip_network_id = body['network']['id']
            cls.addClassResourceCleanup(
                test_utils.call_and_ignore_notfound_exc,
                cls.networks_client.delete_network,
                cls.vip_network_id
            )

            subnet_name = data_utils.rand_name(
                'subnet',
                prefix=cls.name_prefix
            )
            body = cls.subnets_client.create_subnet(
                name=subnet_name,
                network_id=cls.vip_network_id,
                cidr='10.100.1.0/24',
                ip_version=4,
                gateway_ip='10.100.1.1',
            )
            cls.vip_subnet_id = body['subnet']['id']
            cls.addClassResourceCleanup(
                test_utils.call_and_ignore_notfound_exc,
                cls.subnets_client.delete_subnet,
                cls.vip_subnet_id
            )
            cls.member_network_id = cls.vip_network_id
            cls.member_subnet_id = cls.vip_subnet_id

            if CONF.validation.connect_method == 'floating':
                router_name = data_utils.rand_name(
                    'router',
                    prefix=cls.name_prefix
                )
                kwargs = {
                    'name': router_name,
                    'tenant_id': cls.tenant_id
                }
                if CONF.network.public_network_id:
                    kwargs['external_gateway_info'] = dict(
                        network_id=CONF.network.public_network_id
                    )
                body = cls.routers_adm_client.create_router(**kwargs)
                cls.router_id = body['router']['id']
                cls.addClassResourceCleanup(
                    test_utils.call_and_ignore_notfound_exc,
                    cls.routers_adm_client.delete_router,
                    cls.router_id,
                )

                cls.routers_adm_client.add_router_interface(
                    cls.router_id, subnet_id=cls.member_subnet_id
                )
                cls.addClassResourceCleanup(
                    test_utils.call_and_ignore_notfound_exc,
                    cls.routers_adm_client.remove_router_interface,
                    cls.router_id,
                    subnet_id=cls.member_subnet_id
                )
        else:
            cls.vip_network_id = CONF.loadbalancer.vip_network_id
            cls.vip_subnet_id = CONF.loadbalancer.vip_subnet_id
            cls.member_subnet_id = CONF.loadbalancer.premade_server_subnet_id

    @tenacity.retry(
        wait=tenacity.wait_fixed(CONF.loadbalancer.lb_build_interval),
        stop=tenacity.stop_after_delay(CONF.loadbalancer.lb_build_timeout),
        retry=tenacity.retry_if_exception_type(AssertionError)
    )
    def await_loadbalancer_active(self, id, name=None):
        resp, body = self.lb_client.get_obj('loadbalancers', id)
        self.assertEqual(200, resp.status)

        lb = body['loadbalancer']

        if lb['provisioning_status'] == 'ERROR':
            raise Exception('Failed to wait for loadbalancer to be active, '
                            'actual provisioning_status: ERROR')

        self.assertEqual('ACTIVE', lb['provisioning_status'])

        if name:
            self.assertEqual(name, lb['name'])

    @tenacity.retry(
        wait=tenacity.wait_fixed(CONF.loadbalancer.lb_build_interval),
        stop=tenacity.stop_after_delay(CONF.loadbalancer.lb_build_timeout),
        retry=tenacity.retry_if_exception_type(AssertionError)
    )
    def await_loadbalancer_deleted(self, id):
        resp, body = self.lb_client.get_obj('loadbalancers', id)
        self.assertEqual(200, resp.status)

        lb = body['loadbalancer']
        self.assertEqual('DELETED', lb['provisioning_status'])

    @tenacity.retry(
        wait=tenacity.wait_fixed(CONF.loadbalancer.lb_build_interval),
        stop=tenacity.stop_after_delay(CONF.loadbalancer.lb_build_timeout),
        retry=tenacity.retry_if_exception_type(AssertionError)
    )
    def await_listener_active(self, id, name=None):
        resp, body = self.lb_client.get_obj('listeners', id)
        self.assertEqual(200, resp.status)

        listener = body['listener']

        if listener['provisioning_status'] == 'ERROR':
            raise Exception('Failed to wait for listener to be active, actual '
                            'provisioning_status: ERROR')

        self.assertEqual('ACTIVE', listener['provisioning_status'])
        self.assertEqual('ONLINE', listener['operating_status'])

        if name:
            self.assertEqual(name, listener['name'])

    def create_loadbalancer(self, **kwargs):
        name = data_utils.rand_name('lb', prefix=self.name_prefix)
        payload = {'loadbalancer': {'name': name}}
        payload['loadbalancer'].update(kwargs)

        resp, body = self.lb_client.post_json('loadbalancers', payload)
        self.assertEqual(201, resp.status)

        lb = body['loadbalancer']
        lb_id = lb['id']

        self.addCleanup(self.delete_loadbalancer, lb_id, ignore_error=True)
        LOG.info('Waiting for loadbalancer %s to be active', lb_id)
        self.await_loadbalancer_active(
            lb_id,
            name=payload['loadbalancer']['name']
        )

        self.lb_id = lb['id']
        self.vip_port = lb['vip_port_id']
        if CONF.validation.connect_method == 'floating':
            self.vip_address = self._associate_floatingip()
        else:
            self.vip_address = lb['vip_address']

        return lb

    def update_loadbalancer(self, lb_id, **kwargs):
        new_name = data_utils.rand_name('lb', prefix=self.name_prefix)
        payload = {'loadbalancer': {'name': new_name}}
        payload['loadbalancer'].update(kwargs)

        resp, _ = self.lb_client.put_json('loadbalancers', lb_id, payload)
        self.assertEqual(200, resp.status)

        # Wait for loadbalancer to be active
        LOG.info(
            'Waiting for loadbalancer %s to be active after update', lb_id
        )
        self.await_loadbalancer_active(lb_id)

    def delete_loadbalancer(self, id, ignore_error=False):
        """Delete loadbalancer and wait for it to be deleted.

        Only if loadbalancer is deleted completely can other network resources
        be deleted.
        """
        resp = self.lb_client.delete_resource('loadbalancers', id,
                                              ignore_error=ignore_error,
                                              cascade=True)
        if resp:
            self.assertEqual(204, resp.status)

        LOG.info('Waiting for loadbalancer %s to be deleted', id)
        self.await_loadbalancer_deleted(id)

    def create_listener(self, lb_id, **kwargs):
        name = data_utils.rand_name('listener', prefix=self.name_prefix)
        payload = {
            'listener': {
                'protocol': 'HTTP',
                'protocol_port': '80',
                'loadbalancer_id': lb_id,
                'name': name
            }
        }
        payload['listener'].update(kwargs)

        resp, body = self.lb_client.post_json('listeners', payload)
        self.assertEqual(201, resp.status)

        listener_id = body['listener']['id']

        LOG.info(
            'Waiting for loadbalancer %s to be active after listener %s '
            'creation', lb_id, listener_id
        )
        self.addCleanup(self.delete_listener, listener_id, lb_id,
                        ignore_error=True)
        self.await_loadbalancer_active(lb_id)

        return body['listener']

    def update_listener(self, listener_id, lb_id, **kwargs):
        new_name = data_utils.rand_name('listener', prefix=self.name_prefix)
        payload = {'listener': {'name': new_name}}
        payload['listener'].update(kwargs)

        resp, _ = self.lb_client.put_json('listeners', listener_id, payload)
        self.assertEqual(200, resp.status)

        # Wait for loadbalancer to be active
        LOG.info(
            'Waiting for loadbalancer %s to be active after listener %s '
            'update', lb_id, listener_id
        )
        self.await_loadbalancer_active(lb_id)

    def delete_listener(self, id, lb_id, ignore_error=False):
        resp = self.lb_client.delete_resource('listeners', id,
                                              ignore_error=ignore_error)
        if resp:
            self.assertEqual(204, resp.status)

        LOG.info(
            'Waiting for loadbalancer %s to be active after deleting '
            'listener %s', lb_id, id
        )
        self.await_loadbalancer_active(lb_id)

    def create_pool(self, lb_id, **kwargs):
        name = data_utils.rand_name('pool', prefix=self.name_prefix)
        payload = {
            'pool': {
                'name': name,
                'loadbalancer_id': lb_id,
                'lb_algorithm': 'ROUND_ROBIN',
                'protocol': 'HTTP'
            }
        }
        payload['pool'].update(kwargs)

        resp, body = self.lb_client.post_json('pools', payload)
        self.assertEqual(201, resp.status)

        pool_id = body['pool']['id']

        LOG.info(
            'Waiting for loadbalancer %s to be active after pool %s creation',
            lb_id, pool_id
        )
        self.addCleanup(self.delete_pool, pool_id, lb_id, ignore_error=True)
        self.await_loadbalancer_active(lb_id)

        return body['pool']

    def update_pool(self, pool_id, lb_id, **kwargs):
        new_name = data_utils.rand_name('pool', prefix=self.name_prefix)
        payload = {'pool': {'name': new_name}}
        payload['pool'].update(kwargs)

        resp, _ = self.lb_client.put_json('pools', pool_id, payload)
        self.assertEqual(200, resp.status)

        # Wait for loadbalancer to be active
        LOG.info(
            'Waiting for loadbalancer %s to be active after pool %s update',
            lb_id, pool_id
        )
        self.await_loadbalancer_active(lb_id)

    def delete_pool(self, id, lb_id, ignore_error=False):
        resp = self.lb_client.delete_resource('pools', id,
                                              ignore_error=ignore_error)
        if resp:
            self.assertEqual(204, resp.status)

        LOG.info(
            'Waiting for loadbalancer %s to be active after deleting '
            'pool %s', lb_id, id
        )
        self.await_loadbalancer_active(lb_id)

    def create_member(self, pool_id, lb_id, **kwargs):
        name = data_utils.rand_name('member', prefix=self.name_prefix)
        payload = {'member': {'name': name}}
        payload['member'].update(kwargs)

        resp, body = self.lb_client.post_json(
            'pools/%s/members' % pool_id, payload
        )
        self.assertEqual(201, resp.status)

        member_id = body['member']['id']

        LOG.info(
            'Waiting for loadbalancer %s to be active after adding '
            'member %s', lb_id, member_id
        )
        self.addCleanup(self.delete_member, member_id, pool_id,
                        lb_id, ignore_error=True)
        self.await_loadbalancer_active(lb_id)

        return body['member']

    def delete_member(self, id, pool_id, lb_id, ignore_error=False):
        resp = self.lb_client.delete_resource(
            'pools/%s/members' % pool_id,
            id,
            ignore_error=ignore_error
        )
        if resp:
            self.assertEqual(204, resp.status)

        LOG.info(
            'Waiting for loadbalancer %s to be active after deleting '
            'member %s', lb_id, id
        )
        self.await_loadbalancer_active(lb_id)

    def _wait_for_lb_functional(self, vip_address):
        session = requests.Session()
        start = time.time()

        while time.time() - start < CONF.loadbalancer.lb_build_timeout:
            try:
                session.get("http://{0}".format(vip_address), timeout=2)
                time.sleep(1)
                return
            except Exception:
                LOG.warning('Server is not passing initial traffic. Waiting.')
                time.sleep(1)
        LOG.error('Server did not begin passing traffic within the timeout '
                  'period. Failing test.')
        raise lib_exc.ServerFault()

    def check_members_balanced(self):
        session = requests.Session()
        response_counts = {}

        self._wait_for_lb_functional(self.vip_address)

        # Send a number requests to lb vip
        for i in range(20):
            try:
                r = session.get('http://{0}'.format(self.vip_address),
                                timeout=2)
                LOG.debug('Loadbalancer response: %s', r.content)

                if r.content in response_counts:
                    response_counts[r.content] += 1
                else:
                    response_counts[r.content] = 1

            except Exception:
                LOG.exception('Failed to send request to loadbalancer vip')
                raise lib_exc.BadRequest(message='Failed to connect to lb')

        # Ensure the correct number of members
        self.assertEqual(2, len(response_counts))

        # Ensure both members got the same number of responses
        self.assertEqual(1, len(set(response_counts.values())))

    def _delete_floatingip(self, floating_ip):
        self.floatingip_adm_client.update_floatingip(
            floating_ip,
            port_id=None
        )
        test_utils.call_and_ignore_notfound_exc(
            self.floatingip_adm_client.delete_floatingip, floating_ip
        )

    def _associate_floatingip(self):
        # Associate floatingip with loadbalancer vip
        floatingip = self.floatingip_adm_client.create_floatingip(
            floating_network_id=CONF.network.public_network_id
        )['floatingip']
        floatip_vip = floatingip['floating_ip_address']
        self.addCleanup(self._delete_floatingip, floatingip['id'])

        LOG.debug('Floating ip %s created.', floatip_vip)

        self.floatingip_adm_client.update_floatingip(
            floatingip['id'],
            port_id=self.vip_port
        )

        LOG.debug('Floating ip %s associated with vip.', floatip_vip)
        return floatip_vip

    def create_backend(self):
        if CONF.loadbalancer.premade_server_ip:
            self.vm_ip = CONF.loadbalancer.premade_server_ip
            return

        vr_resources = self.vr.resources
        vm = server_util.create_server(
            self.os_roles_lbmember,
            validatable=True,
            validation_resources=vr_resources,
            wait_until='ACTIVE',
            tenant_network=({'id': self.member_network_id}
                            if self.member_network_id else None),
        )
        self.addCleanup(
            server_util.clear_server,
            self.os_roles_lbmember.servers_client,
            vm['id']
        )

        # Get vm private ip address.
        ifaces = self.interfaces_client.list_interfaces(vm['id'])
        for iface in ifaces['interfaceAttachments']:
            if not self.member_network_id or (iface['net_id'] ==
                                              self.vip_network_id):
                for ip_info in iface['fixed_ips']:
                    if not self.vip_subnet_id or (ip_info['subnet_id'] ==
                                                  self.vip_subnet_id):
                        self.vm_ip = ip_info['ip_address']
                        break
            if self.vm_ip:
                break

        self.assertIsNotNone(self.vm_ip)

        if CONF.validation.connect_method == 'floating':
            connect_ip = vr_resources['floating_ip']['floating_ip_address']
        else:
            connect_ip = self.vm_ip

        server_util.run_webserver(
            connect_ip,
            vr_resources['keypair']['private_key']
        )
        LOG.debug('Web servers are running inside %s', vm['id'])
