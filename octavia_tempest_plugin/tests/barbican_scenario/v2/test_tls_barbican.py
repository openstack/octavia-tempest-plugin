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
import requests
import socket
import tempfile

from cryptography.hazmat.primitives import serialization
from OpenSSL.crypto import X509
from OpenSSL import SSL

from oslo_log import log as logging
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

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
        if not CONF.loadbalancer_feature_enabled.l7_protocol_enabled:
            raise cls.skipException(
                '[loadbalancer_feature_enabled] "l7_protocol_enabled" is '
                'False in the tempest configuration. TLS tests will be '
                'skipped.')
        if not CONF.loadbalancer_feature_enabled.terminated_tls_enabled:
            raise cls.skipException(
                '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
                'False in the tempest configuration. TLS tests will be '
                'skipped.')
        if not CONF.validation.run_validation:
            raise cls.skipException('Traffic tests will not work without '
                                    'run_validation enabled.')
        if not getattr(CONF.service_available, 'barbican', False):
            raise cls.skipException('TLS with Barbican tests require the '
                                    'barbican service.')

    @classmethod
    def _store_secret(cls, barbican_mgr, secret):
        new_secret_ref = barbican_mgr.store_secret(secret)
        cls.addClassResourceCleanup(barbican_mgr.delete_secret,
                                    new_secret_ref)

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
            barbican_mgr.add_acl(new_secret_ref, user_list['users'][0]['id'])
        return new_secret_ref

    @classmethod
    def _generate_load_certificate(cls, barbican_mgr, ca_cert, ca_key, name):
        new_cert, new_key = cert_utils.generate_server_cert_and_key(
            ca_cert, ca_key, name)

        LOG.debug('%s Cert: %s', name, new_cert.public_bytes(
            serialization.Encoding.PEM))
        LOG.debug('%s private Key: %s', name, new_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        new_public_key = new_key.public_key()
        LOG.debug('%s public Key: %s', name, new_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

        # Create the pkcs12 bundle
        pkcs12 = cert_utils.generate_pkcs12_bundle(new_cert, new_key)
        LOG.debug('%s PKCS12 bundle: %s', name, base64.b64encode(pkcs12))

        new_secret_ref = cls._store_secret(barbican_mgr, pkcs12)

        return new_cert, new_key, new_secret_ref

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(TLSWithBarbicanTest, cls).resource_setup()

        # Create a CA self-signed cert and key
        cls.ca_cert, ca_key = cert_utils.generate_ca_cert_and_key()

        LOG.debug('CA Cert: %s', cls.ca_cert.public_bytes(
            serialization.Encoding.PEM))
        LOG.debug('CA private Key: %s', ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        LOG.debug('CA public Key: %s', ca_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

        # Load the secret into the barbican service under the
        # os_roles_lb_member tenant
        cls.barbican_mgr = barbican_client_mgr.BarbicanClientManager(
            cls.os_roles_lb_member)

        # Create a server cert and key
        # This will be used as the "default certificate" in SNI tests.
        cls.server_uuid = uuidutils.generate_uuid()
        LOG.debug('Server (default) UUID: %s', cls.server_uuid)

        server_cert, server_key, cls.server_secret_ref = (
            cls._generate_load_certificate(cls.barbican_mgr, cls.ca_cert,
                                           ca_key, cls.server_uuid))

        # Create the SNI1 cert and key
        cls.SNI1_uuid = uuidutils.generate_uuid()
        LOG.debug('SNI1 UUID: %s', cls.SNI1_uuid)

        SNI1_cert, SNI1_key, cls.SNI1_secret_ref = (
            cls._generate_load_certificate(cls.barbican_mgr, cls.ca_cert,
                                           ca_key, cls.SNI1_uuid))

        # Create the SNI2 cert and key
        cls.SNI2_uuid = uuidutils.generate_uuid()
        LOG.debug('SNI2 UUID: %s', cls.SNI2_uuid)

        SNI2_cert, SNI2_key, cls.SNI2_secret_ref = (
            cls._generate_load_certificate(cls.barbican_mgr, cls.ca_cert,
                                           ca_key, cls.SNI2_uuid))

        # Create the client authentication CA
        cls.client_ca_cert, client_ca_key = (
            cert_utils.generate_ca_cert_and_key())

        cls.client_ca_cert_ref = cls._store_secret(
            cls.barbican_mgr,
            cls.client_ca_cert.public_bytes(serialization.Encoding.PEM))

        # Create client cert and key
        cls.client_cn = uuidutils.generate_uuid()
        cls.client_cert, cls.client_key = (
            cert_utils.generate_client_cert_and_key(
                cls.client_ca_cert, client_ca_key, cls.client_cn))

        # Create revoked client cert and key
        cls.revoked_client_cn = uuidutils.generate_uuid()
        cls.revoked_client_cert, cls.revoked_client_key = (
            cert_utils.generate_client_cert_and_key(
                cls.client_ca_cert, client_ca_key, cls.revoked_client_cn))

        # Create certificate revocation list and revoke cert
        cls.client_crl = cert_utils.generate_certificate_revocation_list(
            cls.client_ca_cert, client_ca_key, cls.revoked_client_cert)

        cls.client_crl_ref = cls._store_secret(
            cls.barbican_mgr,
            cls.client_crl.public_bytes(serialization.Encoding.PEM))

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
            const.LB_ALGORITHM: cls.lb_algorithm,
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
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
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
                                    verify=False, protocol_port=443)

        def _verify_cb(connection, x509, errno, errdepth, retcode):
            """Callback for certificate validation."""
            # don't validate names of root certificates
            if errdepth != 0:
                return True
            if errno == 0:
                received_cn = x509.get_subject().commonName
                received_name = self._get_cert_name(received_cn)
                expected_cn = '{}.example.com'.format(self.server_uuid)
                msg = ('ERROR: Received certificate "{received_name}" with CN '
                       '{received_cn} is not the expected certificate '
                       '"default" with CN {expected_cn}.'.format(
                           received_name=received_name,
                           received_cn=received_cn,
                           expected_cn=expected_cn))
                # Make sure the certificate is the one we generated
                self.assertEqual(expected_cn, received_cn, message=msg)
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

    @decorators.idempotent_id('dcf11f78-7af3-4832-b716-9a01648f439c')
    def test_mixed_http_https_traffic(self):

        listener_name = data_utils.rand_name("lb_member_listener1-tls")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
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

        listener_name = data_utils.rand_name("lb_member_listener2-http-tls")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '80',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.listener2_id = listener[const.ID]
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            self.listener2_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Test HTTPS listener load balancing.
        # Note: certificate validation tests will follow this test
        self.check_members_balanced(self.lb_vip_address, protocol='https',
                                    verify=False, protocol_port=443)

        # Test HTTP listener load balancing.
        self.check_members_balanced(self.lb_vip_address)

    @decorators.idempotent_id('08405802-4411-4454-b008-8607408f424a')
    def test_basic_tls_SNI_traffic(self):

        listener_name = data_utils.rand_name("lb_member_listener1-tls-sni")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                       self.SNI2_secret_ref],
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
                                    verify=False, protocol_port=443)

        def _verify_server_cb(connection, x509, errno, errdepth, retcode):
            return _verify_cb(connection, x509, errno, errdepth, retcode,
                              name=self.server_uuid)

        def _verify_SNI1_cb(connection, x509, errno, errdepth, retcode):
            return _verify_cb(connection, x509, errno, errdepth, retcode,
                              name=self.SNI1_uuid)

        def _verify_SNI2_cb(connection, x509, errno, errdepth, retcode):
            return _verify_cb(connection, x509, errno, errdepth, retcode,
                              name=self.SNI2_uuid)

        def _verify_cb(connection, x509, errno, errdepth, retcode, name):
            """Callback for certificate validation."""
            # don't validate names of root certificates
            if errdepth != 0:
                return True
            if errno == 0:
                received_cn = x509.get_subject().commonName
                received_name = self._get_cert_name(received_cn)
                expected_cn = '{}.example.com'.format(name)
                expected_name = self._get_cert_name(name)
                msg = ('ERROR: Received certificate "{received_name}" with CN '
                       '{received_cn} is not the expected certificate '
                       '"{expected_name}" with CN {expected_cn}.'.format(
                           received_name=received_name,
                           received_cn=received_cn,
                           expected_name=expected_name,
                           expected_cn=expected_cn))
                # Make sure the certificate is the one we generated
                self.assertEqual(expected_cn, received_cn, message=msg)
            else:
                LOG.error('Certificate with CN: {0} failed validation with '
                          'OpenSSL verify errno {1}'.format(
                              x509.get_subject().commonName, errno))
                return False
            return True

        # Test that the default certificate is used with no SNI host request
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_server_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the default certificate is used with bogus SNI host request
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_server_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.set_tlsext_host_name('bogus.example.com'.encode())
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the SNI1 certificate is used when SNI1 host is specified
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_SNI1_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.set_tlsext_host_name(
            '{}.example.com'.format(self.SNI1_uuid).encode())
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the SNI2 certificate is used when SNI2 host is specified
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_SNI2_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.set_tlsext_host_name(
            '{}.example.com'.format(self.SNI2_uuid).encode())
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

    def _get_cert_name(self, lookup_string):
        if self.server_uuid in lookup_string:
            return 'default'
        elif self.SNI1_uuid in lookup_string:
            return 'SNI1'
        elif self.SNI2_uuid in lookup_string:
            return 'SNI2'
        else:
            return 'Unknown'

    @decorators.idempotent_id('bfac9bf4-8cd0-4519-8d99-5ad0c75abf5c')
    def test_basic_tls_SNI_multi_listener_traffic(self):
        """Make sure certificates are only used on the correct listeners."""

        listener_name = data_utils.rand_name("lb_member_listener1-tls-sni")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref],
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
                                    verify=False, protocol_port=443)

        listener2_name = data_utils.rand_name("lb_member_listener2-tls-sni")
        listener2_kwargs = {
            const.NAME: listener2_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '8443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.SNI2_secret_ref,
        }
        listener2 = self.mem_listener_client.create_listener(
            **listener2_kwargs)
        self.listener2_id = listener2[const.ID]
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            self.listener2_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Test HTTPS listener load balancing.
        # Note: certificate validation tests will follow this test
        self.check_members_balanced(self.lb_vip_address, protocol='https',
                                    verify=False, protocol_port=8443)

        def _verify_server_cb(connection, x509, errno, errdepth, retcode):
            return _verify_cb(connection, x509, errno, errdepth, retcode,
                              name=self.server_uuid)

        def _verify_SNI1_cb(connection, x509, errno, errdepth, retcode):
            return _verify_cb(connection, x509, errno, errdepth, retcode,
                              name=self.SNI1_uuid)

        def _verify_SNI2_cb(connection, x509, errno, errdepth, retcode):
            return _verify_cb(connection, x509, errno, errdepth, retcode,
                              name=self.SNI2_uuid)

        def _verify_cb(connection, x509, errno, errdepth, retcode, name):
            """Callback for certificate validation."""
            # don't validate names of root certificates
            if errdepth != 0:
                return True
            if errno == 0:
                received_cn = x509.get_subject().commonName
                received_name = self._get_cert_name(received_cn)
                expected_cn = '{}.example.com'.format(name)
                expected_name = self._get_cert_name(name)
                msg = ('ERROR: Received certificate "{received_name}" with CN '
                       '{received_cn} is not the expected certificate '
                       '"{expected_name}" with CN {expected_cn}.'.format(
                           received_name=received_name,
                           received_cn=received_cn,
                           expected_name=expected_name,
                           expected_cn=expected_cn))
                # Make sure the certificate is the one we generated
                self.assertEqual(expected_cn, received_cn, message=msg)
            else:
                LOG.error('Certificate with CN: {0} failed validation with '
                          'OpenSSL verify errno {1}'.format(
                              x509.get_subject().commonName, errno))
                return False
            return True

        # Test that the default certificate is used with no SNI host request
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_server_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the SNI1 certificate is used when SNI1 host is specified
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_SNI1_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.set_tlsext_host_name(
            '{}.example.com'.format(self.SNI1_uuid).encode())
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the default certificate is used when SNI2 host is specified
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_server_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.set_tlsext_host_name(
            '{}.example.com'.format(self.SNI2_uuid).encode())
        sock.connect((self.lb_vip_address, 443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the SNI2 certificate is used with no SNI host request
        # on listener 2, SNI2 is the default cert for listener 2
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_SNI2_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.connect((self.lb_vip_address, 8443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the SNI2 certificate is used with listener 1 host request
        # on listener 2, SNI2 is the default cert for listener 2
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_SNI2_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.set_tlsext_host_name(
            '{}.example.com'.format(self.server_uuid).encode())
        sock.connect((self.lb_vip_address, 8443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

        # Test that the SNI2 certificate is used with SNI1 host request
        # on listener 2, SNI2 is the default cert for listener 2
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           _verify_SNI2_cb)
        ca_store = context.get_cert_store()
        ca_store.add_cert(X509.from_cryptography(self.ca_cert))
        sock = socket.socket()
        sock = SSL.Connection(context, sock)
        sock.set_tlsext_host_name(
            '{}.example.com'.format(self.SNI1_uuid).encode())
        sock.connect((self.lb_vip_address, 8443))
        # Validate the certificate is signed by the ca_cert we created
        sock.do_handshake()

    @decorators.idempotent_id('af6bb7d2-acbb-4f6e-861f-39a2a3f02331')
    def test_tls_client_auth_mandatory(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.8'):
            raise self.skipException('TLS client authentication '
                                     'is only available on Octavia API '
                                     'version 2.8 or newer.')
        LISTENER1_TCP_PORT = '443'
        listener_name = data_utils.rand_name(
            "lb_member_listener1-client-auth-mand")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: LISTENER1_TCP_PORT,
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.CLIENT_AUTHENTICATION: const.CLIENT_AUTH_MANDATORY,
            const.CLIENT_CA_TLS_CONTAINER_REF: self.client_ca_cert_ref,
            const.CLIENT_CRL_CONTAINER_REF: self.client_crl_ref,
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

        # Test that no client certificate fails to connect
        self.assertRaisesRegex(
            requests.exceptions.SSLError, ".*certificate required.*",
            requests.get,
            'https://{0}:{1}'.format(self.lb_vip_address, LISTENER1_TCP_PORT),
            timeout=12, verify=False)

        # Test that a revoked client certificate fails to connect
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.revoked_client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.revoked_client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*revoked.*", requests.get,
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

        # Test that a valid client certificate can connect
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                response = requests.get(
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))
                self.assertEqual(200, response.status_code)

    @decorators.idempotent_id('42d696bf-e7f5-44f0-9331-4a5e01d69ef3')
    def test_tls_client_auth_optional(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.8'):
            raise self.skipException('TLS client authentication '
                                     'is only available on Octavia API '
                                     'version 2.8 or newer.')
        LISTENER1_TCP_PORT = '443'
        listener_name = data_utils.rand_name(
            "lb_member_listener1-client-auth-optional")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: LISTENER1_TCP_PORT,
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.CLIENT_AUTHENTICATION: const.CLIENT_AUTH_OPTIONAL,
            const.CLIENT_CA_TLS_CONTAINER_REF: self.client_ca_cert_ref,
            const.CLIENT_CRL_CONTAINER_REF: self.client_crl_ref,
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

        # Test that no client certificate connects
        response = requests.get(
            'https://{0}:{1}'.format(self.lb_vip_address, LISTENER1_TCP_PORT),
            timeout=12, verify=False)
        self.assertEqual(200, response.status_code)

        # Test that a revoked client certificate fails to connect
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.revoked_client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.revoked_client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*revoked.*", requests.get,
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

        # Test that a valid client certificate can connect
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                response = requests.get(
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))
                self.assertEqual(200, response.status_code)

    @decorators.idempotent_id('13271ce6-f9f7-4017-a017-c2fc390b9438')
    def test_tls_multi_listener_client_auth(self):
        """Test client authentication in a multi-listener LB.

        Validates that certificates and CRLs don't get cross configured
        between multiple listeners on the same load balancer.
        """
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.8'):
            raise self.skipException('TLS client authentication '
                                     'is only available on Octavia API '
                                     'version 2.8 or newer.')
        # Create the client2 authentication CA
        client2_ca_cert, client2_ca_key = (
            cert_utils.generate_ca_cert_and_key())

        client2_ca_cert_ref = self._store_secret(
            self.barbican_mgr,
            client2_ca_cert.public_bytes(serialization.Encoding.PEM))

        # Create client2 cert and key
        client2_cn = uuidutils.generate_uuid()
        client2_cert, client2_key = (
            cert_utils.generate_client_cert_and_key(
                client2_ca_cert, client2_ca_key, client2_cn))

        # Create revoked client2 cert and key
        revoked_client2_cn = uuidutils.generate_uuid()
        revoked_client2_cert, revoked_client2_key = (
            cert_utils.generate_client_cert_and_key(
                client2_ca_cert, client2_ca_key, revoked_client2_cn))

        # Create certificate revocation list and revoke cert
        client2_crl = cert_utils.generate_certificate_revocation_list(
            client2_ca_cert, client2_ca_key, revoked_client2_cert)

        client2_crl_ref = self._store_secret(
            self.barbican_mgr,
            client2_crl.public_bytes(serialization.Encoding.PEM))

        LISTENER1_TCP_PORT = '443'
        listener_name = data_utils.rand_name(
            "lb_member_listener1-multi-list-client-auth")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: LISTENER1_TCP_PORT,
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.CLIENT_AUTHENTICATION: const.CLIENT_AUTH_MANDATORY,
            const.CLIENT_CA_TLS_CONTAINER_REF: self.client_ca_cert_ref,
            const.CLIENT_CRL_CONTAINER_REF: self.client_crl_ref,
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

        LISTENER2_TCP_PORT = '8443'
        listener_name = data_utils.rand_name(
            "lb_member_listener2-multi-list-client-auth")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: LISTENER2_TCP_PORT,
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.CLIENT_AUTHENTICATION: const.CLIENT_AUTH_MANDATORY,
            const.CLIENT_CA_TLS_CONTAINER_REF: client2_ca_cert_ref,
            const.CLIENT_CRL_CONTAINER_REF: client2_crl_ref,
        }
        listener2 = self.mem_listener_client.create_listener(**listener_kwargs)
        self.listener2_id = listener2[const.ID]
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            self.listener2_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Test that no client certificate fails to connect to listener1
        self.assertRaisesRegex(
            requests.exceptions.SSLError, ".*certificate required.*",
            requests.get,
            'https://{0}:{1}'.format(self.lb_vip_address, LISTENER1_TCP_PORT),
            timeout=12, verify=False)

        # Test that no client certificate fails to connect to listener2
        self.assertRaisesRegex(
            requests.exceptions.SSLError, ".*certificate required.*",
            requests.get,
            'https://{0}:{1}'.format(self.lb_vip_address, LISTENER2_TCP_PORT),
            timeout=12, verify=False)

        # Test that a revoked client certificate fails to connect
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.revoked_client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.revoked_client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*revoked.*", requests.get,
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

        # Test that a revoked client2 certificate fails to connect
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(revoked_client2_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(revoked_client2_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*revoked.*", requests.get,
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER2_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

        # Test that a valid client certificate can connect to listener1
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                response = requests.get(
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))
                self.assertEqual(200, response.status_code)

        # Test that a valid client2 certificate can connect to listener2
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(client2_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(client2_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                response = requests.get(
                    'https://{0}:{1}'.format(self.lb_vip_address,
                                             LISTENER2_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))
                self.assertEqual(200, response.status_code)

        # Test that a valid client1 certificate can not connect to listener2
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*decrypt error.*",
                    requests.get, 'https://{0}:{1}'.format(self.lb_vip_address,
                                                           LISTENER2_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

        # Test that a valid client2 certificate can not connect to listener1
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(client2_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(client2_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*decrypt error.*",
                    requests.get, 'https://{0}:{1}'.format(self.lb_vip_address,
                                                           LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

        # Test that a revoked client1 certificate can not connect to listener2
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(self.revoked_client_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(self.revoked_client_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*decrypt error.*",
                    requests.get, 'https://{0}:{1}'.format(self.lb_vip_address,
                                                           LISTENER2_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

        # Test that a revoked client2 certificate can not connect to listener1
        with tempfile.NamedTemporaryFile(buffering=0) as cert_file:
            cert_file.write(revoked_client2_cert.public_bytes(
                serialization.Encoding.PEM))
            with tempfile.NamedTemporaryFile(buffering=0) as key_file:
                key_file.write(revoked_client2_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                self.assertRaisesRegex(
                    requests.exceptions.SSLError, ".*decrypt error.*",
                    requests.get, 'https://{0}:{1}'.format(self.lb_vip_address,
                                                           LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))
