# Copyright 2019 Rackspace US Inc.  All rights reserved.
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

import base64
import socket

from cryptography.hazmat.primitives import serialization
from OpenSSL.crypto import X509
from OpenSSL import SSL

from oslo_log import log as logging
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from octavia_lib.common import constants as lib_consts

from octavia_tempest_plugin.common import barbican_client_mgr
from octavia_tempest_plugin.common import cert_utils
from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TLSWithBarbicanTest(test_base.LoadBalancerBaseTestWithCompute):

    @classmethod
    def skip_checks(cls):
        super(TLSWithBarbicanTest, cls).skip_checks()
        if not CONF.loadbalancer_feature_enabled.terminated_tls_enabled:
            raise cls.skipException('[loadbalancer-feature-enabled] '
                                    '"terminated_tls_enabled" is False in '
                                    'the tempest configuration. TLS tests '
                                    'will be skipped.')
        if not CONF.validation.run_validation:
            raise cls.skipException('Traffic tests will not work without '
                                    'run_validation enabled.')
        if not getattr(CONF.service_available, 'barbican', False):
            raise cls.skipException('TLS with Barbican tests require the '
                                    'barbican service.')

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(TLSWithBarbicanTest, cls).resource_setup()

        # Create a CA self-signed cert and key
        cls.ca_cert, ca_key = cert_utils.generate_ca_cert_and_key()

        LOG.debug('CA Cert: %s' % cls.ca_cert.public_bytes(
            serialization.Encoding.PEM))
        LOG.debug('CA private Key: %s' % ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        LOG.debug('CA public Key: %s' % ca_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

        # Create a server cert and key
        cls.server_uuid = uuidutils.generate_uuid()
        server_cert, server_key = cert_utils.generate_server_cert_and_key(
            cls.ca_cert, ca_key, cls.server_uuid)

        LOG.debug('Server Cert: %s' % server_cert.public_bytes(
            serialization.Encoding.PEM))
        LOG.debug('Server private Key: %s' % server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        server_public_key = server_key.public_key()
        LOG.debug('Server public Key: %s' % server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

        # Create the pkcs12 bundle
        pkcs12 = cert_utils.generate_pkcs12_bundle(server_cert, server_key)
        LOG.debug('Server PKCS12 bundle: %s' % base64.b64encode(pkcs12))

        # Load the secret into the barbican service under the
        # os_roles_lb_member tenant
        barbican_mgr = barbican_client_mgr.BarbicanClientManager(
            cls.os_roles_lb_member)

        cls.secret_ref = barbican_mgr.store_secret(pkcs12)
        cls.addClassResourceCleanup(barbican_mgr.delete_secret, cls.secret_ref)

        # Set the barbican ACL if the Octavia API version doesn't do it
        # automatically.
        if not cls.mem_lb_client.is_version_supported(
                cls.api_version, '2.1'):
            user_list = cls.os_admin.users_v3_client.list_users(
                name=CONF.load_balancer.octavia_svc_username)
            msg = 'Only one user named "{0}" should exist, {1} found.'.format(
                CONF.load_balancer.octavia_svc_username,
                len(user_list['users']))
            assert 1 == len(user_list['users']), msg
            barbican_mgr.add_acl(cls.secret_ref, user_list['users'][0]['id'])

        # Setup a load balancer for the tests to use
        lb_name = data_utils.rand_name("lb_member_lb1-tls")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}

        # TODO(johnsom) Update for IPv6
        cls._setup_lb_network_kwargs(lb_kwargs, 4)

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

        pool_name = data_utils.rand_name("lb_member_pool1-tls")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: const.LB_ALGORITHM_ROUND_ROBIN,
            const.LOADBALANCER_ID: cls.lb_id,
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
        member1_name = data_utils.rand_name("lb_member_member1-tls")
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
        member2_name = data_utils.rand_name("lb_member_member2-tls")
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

    @decorators.idempotent_id('887ece26-0f7b-4933-89ab-5bb00b106ee0')
    def test_basic_tls_traffic(self):

        listener_name = data_utils.rand_name("lb_member_listener1-tls")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: lib_consts.PROTOCOL_TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.secret_ref,
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.listener_id = listener[const.ID]
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            self.listener_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Test HTTPS listener load balancing.
        # Note: certificate validation tests will follow this test
        self.check_members_balanced(self.lb_vip_address, protocol='https',
                                    verify=False)

        def _verify_cb(connection, x509, errno, errdepth, retcode):
            """Callback for certificate validation."""
            # don't validate names of root certificates
            if errdepth != 0:
                return True
            if errno == 0:
                # Make sure the certificate is the one we generated
                self.assertEqual('{}.example.com'.format(self.server_uuid),
                                 x509.get_subject().commonName)
            else:
                LOG.error('Certificate with CN: {0} failed validation with '
                          'OpenSSL verify errno {1}'.format(
                              x509.get_subject().commonName, errno))
                return False
            return True

        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()
