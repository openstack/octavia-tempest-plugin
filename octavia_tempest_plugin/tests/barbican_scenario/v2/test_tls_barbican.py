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
import ssl
import tempfile

from cryptography.hazmat.primitives import serialization
import httpx
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
    def _load_pool_pki(cls):
        # Create the pkcs12 bundle
        pkcs12 = cert_utils.generate_pkcs12_bundle(cls.member_client_cert,
                                                   cls.member_client_key)
        LOG.debug('Pool client PKCS12 bundle: %s', base64.b64encode(pkcs12))

        cls.pool_client_ref = cls._store_secret(cls.barbican_mgr, pkcs12)

        cls.pool_CA_ref = cls._store_secret(
            cls.barbican_mgr,
            cls.member_ca_cert.public_bytes(serialization.Encoding.PEM))

        cls.pool_CRL_ref = cls._store_secret(
            cls.barbican_mgr,
            cls.member_crl.public_bytes(serialization.Encoding.PEM))

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

        cls._load_pool_pki()

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
            cls.lb_id, cascade=True)

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

        cls.mem_member_client.create_member(**member1_kwargs)
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

        cls.mem_member_client.create_member(**member2_kwargs)
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
        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTPS,
                                    HTTPS_verify=False, protocol_port=443)

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

        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTPS,
                                    HTTPS_verify=False, protocol_port=443)

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
        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTPS,
                                    HTTPS_verify=False, protocol_port=443)

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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTPS,
                                    HTTPS_verify=False, protocol_port=443)

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
        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTPS,
                                    HTTPS_verify=False, protocol_port=8443)

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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        try:
            context = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
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
        self.assertRaises(
            requests.exceptions.SSLError,
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
                self.assertRaises(
                    requests.exceptions.SSLError, requests.get,
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
                self.assertRaises(
                    requests.exceptions.SSLError, requests.get,
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
        self.assertRaises(
            requests.exceptions.SSLError,
            requests.get,
            'https://{0}:{1}'.format(self.lb_vip_address, LISTENER1_TCP_PORT),
            timeout=12, verify=False)

        # Test that no client certificate fails to connect to listener2
        self.assertRaises(
            requests.exceptions.SSLError,
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
                self.assertRaises(
                    requests.exceptions.SSLError, requests.get,
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
                self.assertRaises(
                    requests.exceptions.SSLError, requests.get,
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
                self.assertRaises(
                    requests.exceptions.SSLError,
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
                self.assertRaises(
                    requests.exceptions.SSLError,
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
                self.assertRaises(
                    requests.exceptions.SSLError,
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
                self.assertRaises(
                    requests.exceptions.SSLError,
                    requests.get, 'https://{0}:{1}'.format(self.lb_vip_address,
                                                           LISTENER1_TCP_PORT),
                    timeout=12, verify=False, cert=(cert_file.name,
                                                    key_file.name))

    @decorators.idempotent_id('19bade6f-302f-45dc-b316-553f1dfff49c')
    def test_alpn_tls_traffic(self):
        """Test ALPN protocol negotiation"""
        s_protos = c_protos = ['http/1.1']
        expected = 'http/1.1'
        self._test_alpn_tls_traffic(s_protos, c_protos, expected)

    @decorators.idempotent_id('ee0d15a3-05b7-498d-9b2f-280d4896e597')
    def test_alpn_fallback_tls_traffic(self):
        """Test ALPN protocol negotiation fallback"""
        s_protos = ['http/1.0', 'http/1.1']
        c_protos = ['bogus', 'h2', 'http/1.1']
        expected = 'http/1.1'
        self._test_alpn_tls_traffic(s_protos, c_protos, expected)

    @decorators.idempotent_id('56f4274a-ebd9-42f7-b897-baebc4b8eb5b')
    def test_alpn_proto_not_supported_tls_traffic(self):
        """Test failed ALPN protocol negotiation"""
        s_protos = ['http/1.1', 'http/1.0']
        c_protos = ['h2']
        expected = None
        self._test_alpn_tls_traffic(s_protos, c_protos, expected)

    def _test_alpn_tls_traffic(self, s_protos, c_protos, expected_proto):
        """Test ALPN protocols between client and load balancer.

        :param s_protos: ALPN protocols the load balancer accepts during the
                         SSL/TLS handshake.
        :type s_protos: list of str
        :param c_protos: ALPN protocols the client advertise during SSL/TLS the
                         handshake.
        :type c_protos: list of str
        :param expected_proto: the expected ALPN protocol selected during the
                               SSL/TLS handshake. Setting to ``None`` means
                               parties could not agree on ALPN protocol.
        :type expected_proto: str
        :raises self.skipException: ALPN support not available prior to v2.20.
        """
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.20'):
            raise self.skipException('ALPN protocols are only available on '
                                     'Octavia API version 2.20 or newer.')
        listener_name = data_utils.rand_name("lb_member_listener1-tls-alpn")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.ALPN_PROTOCOLS: s_protos,
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

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_alpn_protocols(c_protos)
        s = socket.socket()
        ssl_sock = context.wrap_socket(s)
        ssl_sock.connect((self.lb_vip_address, 443))
        selected_proto = ssl_sock.selected_alpn_protocol()

        self.assertEqual(expected_proto, selected_proto)

    def _test_http_versions_tls_traffic(self, http_version, alpn_protos):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.20'):
            raise self.skipException('ALPN protocols are only available on '
                                     'Octavia API version 2.20 or newer.')
        listener_name = data_utils.rand_name("lb_member_listener1-tls-alpn")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.TERMINATED_HTTPS,
            const.PROTOCOL_PORT: '443',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: self.pool_id,
            const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
            const.ALPN_PROTOCOLS: alpn_protos,
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

        context = ssl.create_default_context(cadata=self.ca_cert.public_bytes(
            serialization.Encoding.PEM).decode('utf-8'))
        context.check_hostname = False

        url = 'https://%s:%s' % (self.lb_vip_address, 443)
        client = httpx.Client(http2=(http_version == 'HTTP/2'), verify=context)
        r = client.get(url)
        self.assertEqual(http_version, r.http_version)

    @decorators.idempotent_id('9965828d-24af-4fa0-91ae-21c6bc47ab4c')
    def test_http_2_tls_traffic(self):
        self._test_http_versions_tls_traffic('HTTP/2', ['h2', 'http/1.1'])

    @decorators.idempotent_id('a0dff0f2-d53e-497c-9ded-dca64e82991f')
    def test_http_1_1_tls_traffic(self):
        self._test_http_versions_tls_traffic(
            'HTTP/1.1', ['http/1.1', 'http/1.0'])

    @decorators.idempotent_id('ee0faf71-d11e-4323-8673-e5e15779749b')
    def test_pool_reencryption(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.8'):
            raise self.skipException('Pool re-encryption is only available on '
                                     'Octavia API version 2.8 or newer.')
        pool_name = data_utils.rand_name("lb_member_pool1-tls-reencrypt")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: self.lb_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
            const.TLS_ENABLED: True
        }
        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        pool_id = pool[const.ID]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name("lb_member_member1-tls-reencrypt")
        member1_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver1_ip,
            const.PROTOCOL_PORT: 443,
        }
        if self.lb_member_1_subnet:
            member1_kwargs[const.SUBNET_ID] = self.lb_member_1_subnet[const.ID]

        self.mem_member_client.create_member(**member1_kwargs)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name("lb_member_member2-tls-reencrypt")
        member2_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 443,
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

        self.mem_member_client.create_member(**member2_kwargs)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        listener_name = data_utils.rand_name(
            "lb_member_listener1-tls-reencrypt")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '84',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: pool_id,
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.listener_id = listener[const.ID]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Test with no CA validation
        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTP,
                                    protocol_port=84)

        # Test with CA validation - invalid CA
        pool_update_kwargs = {
            const.CA_TLS_CONTAINER_REF: self.client_ca_cert_ref
        }

        self.mem_pool_client.update_pool(pool_id, **pool_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        waiters.wait_for_status(
            self.mem_pool_client.show_pool, pool_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        url = 'http://{0}:84'.format(self.lb_vip_address)
        self.validate_URL_response(url, expected_status_code=503)

        # Test with CA validation - valid CA
        pool_update_kwargs = {
            const.CA_TLS_CONTAINER_REF: self.pool_CA_ref
        }

        self.mem_pool_client.update_pool(pool_id, **pool_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        waiters.wait_for_status(
            self.mem_pool_client.show_pool, pool_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTP,
                                    protocol_port=84)

        # Test with CRL including one webserver certificate revoked
        pool_update_kwargs = {
            const.CRL_CONTAINER_REF: self.pool_CRL_ref
        }

        self.mem_pool_client.update_pool(pool_id, **pool_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        waiters.wait_for_status(
            self.mem_pool_client.show_pool, pool_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTP,
                                    protocol_port=84, traffic_member_count=1)

    @decorators.idempotent_id('11b67c96-a553-4b47-9fc6-4c3d7a2a10ce')
    def test_pool_reencryption_client_authentication(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.8'):
            raise self.skipException('Pool re-encryption is only available on '
                                     'Octavia API version 2.8 or newer.')
        pool_name = data_utils.rand_name("lb_member_pool1-tls-client-auth")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: const.HTTP,
            const.LB_ALGORITHM: self.lb_algorithm,
            const.LOADBALANCER_ID: self.lb_id,
            const.TLS_ENABLED: True
        }
        # Specify an http/1.x alpn to work around HTTP healthchecks
        # on older haproxy versions when alpn includes h2
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.24'):
            pool_kwargs[const.ALPN_PROTOCOLS] = ['http/1.0', 'http/1.1']

        pool = self.mem_pool_client.create_pool(**pool_kwargs)
        pool_id = pool[const.ID]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        hm_name = data_utils.rand_name("lb_member_hm1-tls-client-auth")
        hm_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: hm_name,
            const.TYPE: const.HEALTH_MONITOR_HTTPS,
            const.HTTP_METHOD: const.GET,
            const.URL_PATH: '/',
            const.EXPECTED_CODES: '200',
            const.DELAY: 1,
            const.TIMEOUT: 1,
            const.MAX_RETRIES: 1,
            const.MAX_RETRIES_DOWN: 1,
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

        # Set up Member 1 for Webserver 1
        member1_name = data_utils.rand_name(
            "lb_member_member1-tls-client-auth")
        member1_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver1_ip,
            const.PROTOCOL_PORT: 9443,
        }
        if self.lb_member_1_subnet:
            member1_kwargs[const.SUBNET_ID] = self.lb_member_1_subnet[const.ID]

        self.mem_member_client.create_member(**member1_kwargs)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        # Set up Member 2 for Webserver 2
        member2_name = data_utils.rand_name(
            "lb_member_member2-tls-client-auth")
        member2_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: self.webserver2_ip,
            const.PROTOCOL_PORT: 9443,
        }
        if self.lb_member_2_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_2_subnet[const.ID]

        self.mem_member_client.create_member(**member2_kwargs)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        listener_name = data_utils.rand_name(
            "lb_member_listener1-tls-client-auth")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: const.HTTP,
            const.PROTOCOL_PORT: '85',
            const.LOADBALANCER_ID: self.lb_id,
            const.DEFAULT_POOL_ID: pool_id,
        }
        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.listener_id = listener[const.ID]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        # Test that there are no members without a client certificate
        url = 'http://{0}:85'.format(self.lb_vip_address)
        self.validate_URL_response(url, expected_status_code=503)

        # Test with client certificates
        pool_update_kwargs = {
            const.TLS_CONTAINER_REF: self.pool_client_ref
        }

        self.mem_pool_client.update_pool(pool_id, **pool_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
        waiters.wait_for_status(
            self.mem_pool_client.show_pool, pool_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        self.check_members_balanced(self.lb_vip_address, protocol=const.HTTP,
                                    protocol_port=85)
