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

import base64
import time
from uuid import UUID

from cryptography.hazmat.primitives import serialization

from dateutil import parser
from oslo_log import log as logging
from oslo_utils import strutils
from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions
import testtools

from octavia_tempest_plugin.common import barbican_client_mgr
from octavia_tempest_plugin.common import cert_utils
from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ListenerAPITest(test_base.LoadBalancerBaseTest):
    """Test the listener object API."""

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
            cls.assertEqual(1, len(user_list['users']), msg)
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
        # Create the member client authentication CA
        cls.member_client_ca_cert, member_client_ca_key = (
            cert_utils.generate_ca_cert_and_key())

        # Create client cert and key
        cls.member_client_cn = uuidutils.generate_uuid()
        cls.member_client_cert, cls.member_client_key = (
            cert_utils.generate_client_cert_and_key(
                cls.member_client_ca_cert, member_client_ca_key,
                cls.member_client_cn))

        # Create the pkcs12 bundle
        pkcs12 = cert_utils.generate_pkcs12_bundle(cls.member_client_cert,
                                                   cls.member_client_key)
        LOG.debug('Pool client PKCS12 bundle: %s', base64.b64encode(pkcs12))

        cls.pool_client_ref = cls._store_secret(cls.barbican_mgr, pkcs12)

        cls.member_ca_cert, cls.member_ca_key = (
            cert_utils.generate_ca_cert_and_key())

        cert, key = cert_utils.generate_server_cert_and_key(
            cls.member_ca_cert, cls.member_ca_key, cls.server_uuid)

        cls.pool_CA_ref = cls._store_secret(
            cls.barbican_mgr,
            cls.member_ca_cert.public_bytes(serialization.Encoding.PEM))

        cls.member_crl = cert_utils.generate_certificate_revocation_list(
            cls.member_ca_cert, cls.member_ca_key, cert)

        cls.pool_CRL_ref = cls._store_secret(
            cls.barbican_mgr,
            cls.member_crl.public_bytes(serialization.Encoding.PEM))

    @classmethod
    def should_apply_terminated_https(cls, protocol=None):
        if protocol and protocol != const.TERMINATED_HTTPS:
            return False
        return CONF.load_balancer.test_with_noop or getattr(
            CONF.service_available, 'barbican', False)

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(ListenerAPITest, cls).resource_setup()

        if CONF.load_balancer.test_with_noop:
            cls.server_secret_ref = uuidutils.generate_uuid()
            cls.SNI1_secret_ref = uuidutils.generate_uuid()
            cls.SNI2_secret_ref = uuidutils.generate_uuid()
        elif getattr(CONF.service_available, 'barbican', False):
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

        lb_name = data_utils.rand_name("lb_member_lb1_listener")
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

        cls.allowed_cidrs = ['192.0.1.0/24']
        if CONF.load_balancer.test_with_ipv6:
            cls.allowed_cidrs = ['2001:db8:a0b:12f0::/64']

    @classmethod
    def setup_clients(cls):
        """Setup client aliases."""
        super(ListenerAPITest, cls).setup_clients()
        cls.listener_client = cls.os_primary.load_balancer_v2.ListenerClient()
        cls.member2_listener_client = (
            cls.os_roles_lb_member2.load_balancer_v2.ListenerClient())

    @decorators.idempotent_id('88d0ec83-7b08-48d9-96e2-0df1d2f8cd98')
    def test_http_listener_create(self):
        self._test_listener_create(const.HTTP, 8000)

    @decorators.idempotent_id('2cc89237-fc6b-434d-b38e-b3309823e71f')
    def test_https_listener_create(self):
        self._test_listener_create(const.HTTPS, 8001)

    @decorators.idempotent_id('45580065-5653-436b-aaff-dc465fa0a542')
    def test_tcp_listener_create(self):
        self._test_listener_create(const.TCP, 8002)

    @decorators.idempotent_id('1a6ba0d0-f309-4088-a686-dda0e9ab7e43')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.prometheus_listener_enabled,
        'PROMETHEUS listener tests are disabled in the tempest configuration.')
    def test_prometheus_listener_create(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.25'):
            raise self.skipException('PROMETHEUS listeners are only available '
                                     'on Octavia API version 2.25 or newer.')
        self._test_listener_create(const.PROMETHEUS, 8090)

    @decorators.idempotent_id('df9861c5-4a2a-4122-8d8f-5556156e343e')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_terminated_https_listener_create(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_create(const.TERMINATED_HTTPS, 8095)

    @decorators.idempotent_id('7b53f336-47bc-45ae-bbd7-4342ef0673fc')
    def test_udp_listener_create(self):
        self._test_listener_create(const.UDP, 8003)

    @decorators.idempotent_id('d6d36c32-27ff-4977-9d21-fd71a14e3b20')
    def test_sctp_listener_create(self):
        self._test_listener_create(const.SCTP, 8004)

    def _test_listener_create(self, protocol, protocol_port):
        """Tests listener create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create listeners.
        * Create a fully populated listener.
        * Show listener details.
        * Validate the show reflects the requested values.
        """
        self._validate_listener_protocol(protocol)

        listener_name = data_utils.rand_name("lb_member_listener1-create")
        listener_description = data_utils.arbitrary_string(size=255)
        hsts_supported = self.mem_listener_client.is_version_supported(
            self.api_version, '2.27') and protocol == const.TERMINATED_HTTPS

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            # Don't test with a default pool -- we'll do that in the scenario,
            # but this will allow us to test that the field isn't mandatory,
            # as well as not conflate pool failures with listener test failures
            # const.DEFAULT_POOL_ID: self.pool_id,
        }
        if protocol == const.HTTP:
            listener_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true",
                const.X_FORWARDED_PROTO: "true",
            }

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_tags = [str(x) for x in range(100)]
            listener_kwargs.update({
                const.TAGS: listener_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            # Test that CIDR IP version matches VIP IP version
            bad_cidrs = ['192.0.1.0/24', '2001:db8:a0b:12f0::/64']
            listener_kwargs.update({const.ALLOWED_CIDRS: bad_cidrs})
            self.assertRaises(
                exceptions.BadRequest,
                self.mem_listener_client.create_listener,
                **listener_kwargs)
            listener_kwargs.update({const.ALLOWED_CIDRS: self.allowed_cidrs})

        if hsts_supported:
            listener_kwargs[const.HSTS_PRELOAD] = True
            listener_kwargs[const.HSTS_MAX_AGE] = 10000
            listener_kwargs[const.HSTS_INCLUDE_SUBDOMAINS] = True

        # Test that a user without the loadbalancer role cannot
        # create a listener.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'ListenerClient', 'create_listener',
                expected_allowed,
                status_method=self.mem_lb_client.show_loadbalancer,
                obj_id=self.lb_id, **listener_kwargs)

        listener = self.mem_listener_client.create_listener(**listener_kwargs)

        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        equal_items = [const.NAME, const.DESCRIPTION,
                       const.ADMIN_STATE_UP,
                       const.PROTOCOL, const.PROTOCOL_PORT,
                       const.CONNECTION_LIMIT]

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.TIMEOUT_CLIENT_DATA)
            equal_items.append(const.TIMEOUT_MEMBER_CONNECT)
            equal_items.append(const.TIMEOUT_MEMBER_DATA)
            equal_items.append(const.TIMEOUT_TCP_INSPECT)

        if hsts_supported:
            equal_items.append(const.HSTS_PRELOAD)
            equal_items.append(const.HSTS_MAX_AGE)
            equal_items.append(const.HSTS_INCLUDE_SUBDOMAINS)

        for item in equal_items:
            self.assertEqual(listener_kwargs[item], listener[item])

        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])

        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            self.assertEqual(self.server_secret_ref,
                             listener[const.DEFAULT_TLS_CONTAINER_REF])
            self.assertEqual(sorted([self.SNI1_secret_ref,
                                     self.SNI2_secret_ref]),
                             sorted(listener[const.SNI_CONTAINER_REFS]))

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_kwargs[const.TAGS],
                                  listener[const.TAGS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            self.assertEqual(self.allowed_cidrs, listener[const.ALLOWED_CIDRS])

    @decorators.idempotent_id('cceac303-4db5-4d5a-9f6e-ff33780a5f29')
    def test_http_udp_sctp_tcp_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.HTTP, const.UDP,
                                                const.SCTP,
                                                const.TCP, 8010)

    @decorators.idempotent_id('930338b8-3029-48a6-89b2-8b062060fe61')
    def test_http_udp_sctp_https_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.HTTP, const.UDP,
                                                const.SCTP,
                                                const.HTTPS, 8011)

    @decorators.idempotent_id('01a21892-008a-4327-b4fd-fbf194ecb1a5')
    def test_tcp_udp_sctp_http_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.TCP, const.UDP,
                                                const.SCTP,
                                                const.HTTP, 8012)

    @decorators.idempotent_id('5da764a4-c03a-46ed-848b-98b9d9fa9089')
    def test_tcp_udp_sctp_https_listener_create_on_same_port(self):
        self._test_listener_create_on_same_port(const.TCP, const.UDP,
                                                const.SCTP,
                                                const.HTTPS, 8013)

    @decorators.idempotent_id('128dabd0-3a9b-4c11-9ef5-8d189a290f17')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_http_udp_sctp_terminated_https_listener_create_on_same_port(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_create_on_same_port(const.HTTP, const.UDP,
                                                const.SCTP,
                                                const.TERMINATED_HTTPS, 8014)

    @decorators.idempotent_id('21da2598-c79e-4548-8fe0-b47749027010')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_tcp_udp_sctp_terminated_https_listener_create_on_same_port(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_create_on_same_port(const.TCP, const.UDP,
                                                const.SCTP,
                                                const.TERMINATED_HTTPS, 8015)

    def _test_listener_create_on_same_port(self, protocol1, protocol2,
                                           protocol3, protocol4,
                                           protocol_port):
        """Tests listener creation on same port number.

        * Create a first listener.
        * Create a new listener on an existing port, but with a different
          protocol.
        * Create a second listener with the same parameters and ensure that
          an error is triggered.
        * Create a third listener on an existing port, but with a different
          protocol.
        * Create a fourth listener with another protocol over TCP, and ensure
          that it fails.
        """

        skip_protocol1 = (
            not self._validate_listener_protocol(protocol1,
                                                 raise_if_unsupported=False))
        skip_protocol2 = (
            not self._validate_listener_protocol(protocol2,
                                                 raise_if_unsupported=False))
        skip_protocol3 = (
            not self._validate_listener_protocol(protocol3,
                                                 raise_if_unsupported=False))
        skip_protocol4 = (
            not self._validate_listener_protocol(protocol4,
                                                 raise_if_unsupported=False))

        # Using listeners on the same port for TCP and UDP was not supported
        # before Train. Use 2.11 API version as reference to detect previous
        # releases and skip the test.
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.11'):
            raise self.skipException('TCP and UDP listeners on same port fix '
                                     'is only available on Octavia API '
                                     'version 2.11 or newer.')

        if not skip_protocol1:
            listener_name = data_utils.rand_name("lb_member_listener1-create")

            listener_kwargs = {
                const.NAME: listener_name,
                const.ADMIN_STATE_UP: True,
                const.PROTOCOL: protocol1,
                const.PROTOCOL_PORT: protocol_port,
                const.LOADBALANCER_ID: self.lb_id,
                const.CONNECTION_LIMIT: 200
            }

            try:
                self.mem_listener_client.create_listener(**listener_kwargs)
            except exceptions.BadRequest as e:
                fs = e.resp_body.get('faultstring', '')
                if ("Invalid input for field/attribute protocol." in fs
                        and "Value should be one of:" in fs):
                    LOG.info("Skipping unsupported protocol: {}".format(
                        listener_kwargs[const.PROTOCOL]))
                else:
                    raise e
            else:
                waiters.wait_for_status(
                    self.mem_lb_client.show_loadbalancer, self.lb_id,
                    const.PROVISIONING_STATUS, const.ACTIVE,
                    CONF.load_balancer.build_interval,
                    CONF.load_balancer.build_timeout)

        if not skip_protocol2:
            # Create a listener on the same port, but with a different protocol
            listener2_name = data_utils.rand_name("lb_member_listener2-create")

            listener2_kwargs = {
                const.NAME: listener2_name,
                const.ADMIN_STATE_UP: True,
                const.PROTOCOL: protocol2,
                const.PROTOCOL_PORT: protocol_port,
                const.LOADBALANCER_ID: self.lb_id,
                const.CONNECTION_LIMIT: 200,
            }

            try:
                self.mem_listener_client.create_listener(**listener2_kwargs)
            except exceptions.BadRequest as e:
                fs = e.resp_body.get('faultstring', '')
                if ("Invalid input for field/attribute protocol." in fs
                        and "Value should be one of:" in fs):
                    LOG.info("Skipping unsupported protocol: {}".format(
                        listener_kwargs[const.PROTOCOL]))
                else:
                    raise e
            else:
                waiters.wait_for_status(
                    self.mem_lb_client.show_loadbalancer, self.lb_id,
                    const.PROVISIONING_STATUS, const.ACTIVE,
                    CONF.load_balancer.build_interval,
                    CONF.load_balancer.build_timeout)

        if not skip_protocol1:
            # Create a listener on the same port, with an already used protocol
            listener3_name = data_utils.rand_name("lb_member_listener3-create")

            listener3_kwargs = {
                const.NAME: listener3_name,
                const.ADMIN_STATE_UP: True,
                const.PROTOCOL: protocol1,
                const.PROTOCOL_PORT: protocol_port,
                const.LOADBALANCER_ID: self.lb_id,
                const.CONNECTION_LIMIT: 200,
            }

            self.assertRaises(
                exceptions.Conflict,
                self.mem_listener_client.create_listener,
                **listener3_kwargs)

        if not skip_protocol3:
            # Create a listener on the same port, with a different protocol
            listener4_name = data_utils.rand_name("lb_member_listener4-create")

            listener4_kwargs = {
                const.NAME: listener4_name,
                const.ADMIN_STATE_UP: True,
                const.PROTOCOL: protocol3,
                const.PROTOCOL_PORT: protocol_port,
                const.LOADBALANCER_ID: self.lb_id,
                const.CONNECTION_LIMIT: 200,
            }

            try:
                self.mem_listener_client.create_listener(**listener4_kwargs)
            except exceptions.BadRequest as e:
                fs = e.resp_body.get('faultstring', '')
                if ("Invalid input for field/attribute protocol." in fs
                        and "Value should be one of:" in fs):
                    LOG.info("Skipping unsupported protocol: {}".format(
                        listener_kwargs[const.PROTOCOL]))
                else:
                    raise e
            else:
                waiters.wait_for_status(
                    self.mem_lb_client.show_loadbalancer, self.lb_id,
                    const.PROVISIONING_STATUS, const.ACTIVE,
                    CONF.load_balancer.build_interval,
                    CONF.load_balancer.build_timeout)

        if not skip_protocol4:
            # Create a listener on the same port, with another protocol over
            # TCP
            listener5_name = data_utils.rand_name("lb_member_listener5-create")

            listener5_kwargs = {
                const.NAME: listener5_name,
                const.ADMIN_STATE_UP: True,
                const.PROTOCOL: protocol4,
                const.PROTOCOL_PORT: protocol_port,
                const.LOADBALANCER_ID: self.lb_id,
                const.CONNECTION_LIMIT: 200,
            }

            # Add terminated_https args
            if self.should_apply_terminated_https(protocol=protocol4):
                listener5_kwargs.update({
                    const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                    const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                               self.SNI2_secret_ref],
                })

            self.assertRaises(
                exceptions.Conflict,
                self.mem_listener_client.create_listener,
                **listener5_kwargs)

    @decorators.idempotent_id('78ba6eb0-178c-477e-9156-b6775ca7b271')
    def test_http_listener_list(self):
        self._test_listener_list(const.HTTP, 8020)

    @decorators.idempotent_id('61b7c643-f5fa-4471-8f9e-2e0ccdaf5ac7')
    def test_https_listener_list(self):
        self._test_listener_list(const.HTTPS, 8030)

    @decorators.idempotent_id('5473e071-8277-4ac5-9277-01ecaf46e274')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.prometheus_listener_enabled,
        'PROMETHEUS listener tests are disabled in the tempest configuration.')
    def test_prometheus_listener_list(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.25'):
            raise self.skipException('PROMETHEUS listeners are only available '
                                     'on Octavia API version 2.25 or newer.')
        self._test_listener_list(const.PROMETHEUS, 8091)

    @decorators.idempotent_id('1cd476e2-7788-415e-bcaf-c377acfc9794')
    def test_tcp_listener_list(self):
        self._test_listener_list(const.TCP, 8030)

    @decorators.idempotent_id('c08fb77e-b317-4d6f-b430-91f5b27ebac6')
    def test_udp_listener_list(self):
        self._test_listener_list(const.UDP, 8040)

    @decorators.idempotent_id('0abc3998-aacd-4edd-88f5-c5c35557646f')
    def test_sctp_listener_list(self):
        self._test_listener_list(const.SCTP, 8041)

    @decorators.idempotent_id('aed69f58-fe69-401d-bf07-37b0d6d8437f')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_terminated_https_listener_list(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_list(const.TERMINATED_HTTPS, 8042)

    def _test_listener_list(self, protocol, protocol_port_base):
        """Tests listener list API and field filtering.

        * Create a clean loadbalancer.
        * Create three listeners.
        * Validates that other accounts cannot list the listeners.
        * List the listeners using the default sort order.
        * List the listeners using descending sort order.
        * List the listeners using ascending sort order.
        * List the listeners returning one field at a time.
        * List the listeners returning two fields.
        * List the listeners filtering to one of the three.
        * List the listeners filtered, one field, and sorted.
        """
        # IDs of listeners created in the test
        test_ids = []

        self._validate_listener_protocol(protocol)

        lb_name = data_utils.rand_name("lb_member_lb2_listener-list")
        lb = self.mem_lb_client.create_loadbalancer(
            name=lb_name, provider=CONF.load_balancer.provider,
            vip_network_id=self.lb_member_vip_net[const.ID])
        lb_id = lb[const.ID]
        self.addCleanup(
            self.mem_lb_client.cleanup_loadbalancer,
            lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

        listener1_name = data_utils.rand_name("lb_member_listener2-list")
        listener1_desc = 'B'
        listener1_kwargs = {
            const.NAME: listener1_name,
            const.DESCRIPTION: listener1_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port_base,
            const.LOADBALANCER_ID: lb_id,
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener1_tags = ["English", "Mathematics",
                              "Marketing", "Creativity"]
            listener1_kwargs.update({const.TAGS: listener1_tags})

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener1_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        listener1 = self.mem_listener_client.create_listener(
            **listener1_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener1[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        listener1 = waiters.wait_for_status(
            self.mem_listener_client.show_listener, listener1[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(listener1[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        listener2_name = data_utils.rand_name("lb_member_listener1-list")
        listener2_desc = 'A'
        listener2_kwargs = {
            const.NAME: listener2_name,
            const.DESCRIPTION: listener2_desc,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port_base + 1,
            const.LOADBALANCER_ID: lb_id,
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener2_tags = ["English", "Spanish",
                              "Soft_skills", "Creativity"]
            listener2_kwargs.update({const.TAGS: listener2_tags})

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener2_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        listener2 = self.mem_listener_client.create_listener(
            **listener2_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener2[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        listener2 = waiters.wait_for_status(
            self.mem_listener_client.show_listener, listener2[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(listener2[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        listener3_name = data_utils.rand_name("lb_member_listener3-list")
        listener3_desc = 'C'
        listener3_kwargs = {
            const.NAME: listener3_name,
            const.DESCRIPTION: listener3_desc,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port_base + 2,
            const.LOADBALANCER_ID: lb_id,
        }
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener3_tags = ["English", "Project_management",
                              "Communication", "Creativity"]
            listener3_kwargs.update({const.TAGS: listener3_tags})

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener3_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        listener3 = self.mem_listener_client.create_listener(
            **listener3_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener3[const.ID],
            lb_client=self.mem_lb_client, lb_id=lb_id)
        listener3 = waiters.wait_for_status(
            self.mem_listener_client.show_listener, listener3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        test_ids.append(listener3[const.ID])

        if not CONF.load_balancer.test_with_noop:
            # Wait for the enabled listeners to come ONLINE
            listener1 = waiters.wait_for_status(
                self.mem_listener_client.show_listener, listener1[const.ID],
                const.OPERATING_STATUS, const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)
            listener2 = waiters.wait_for_status(
                self.mem_listener_client.show_listener, listener2[const.ID],
                const.OPERATING_STATUS, const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)
            listener3 = waiters.wait_for_status(
                self.mem_listener_client.show_listener, listener3[const.ID],
                const.OPERATING_STATUS, const.OFFLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        # Test that a different users cannot see the lb_member listeners.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_primary', 'os_roles_lb_member2']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_primary', 'os_roles_lb_member2',
                                'os_roles_lb_observer',
                                'os_roles_lb_global_observer']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_roles_lb_observer', 'os_roles_lb_member2']
        if expected_allowed:
            self.check_list_RBAC_enforcement_count(
                'ListenerClient', 'list_listeners', expected_allowed, 0,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

        # Test credentials that should see these listeners can see them.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_system_reader', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin', 'os_roles_lb_member',
                                'os_roles_lb_global_observer']
        if expected_allowed:
            self.check_list_IDs_RBAC_enforcement(
                'ListenerClient', 'list_listeners', expected_allowed,
                test_ids,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

        # Test that users without the lb member role cannot list listeners.
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
            expected_allowed = ['os_admin', 'os_primary', 'os_roles_lb_admin',
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
                'ListenerClient', 'list_listeners', expected_allowed,
                query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))

        # Check the default sort order, created_at
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}'.format(lb_id=lb_id))
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener3[const.DESCRIPTION],
                         listeners[2][const.DESCRIPTION])

        # Test sort descending by description
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{sort}={descr}:{desc}'
                         .format(lb_id=lb_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, desc=const.DESC))
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[2][const.DESCRIPTION])
        self.assertEqual(listener3[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])

        # Test sort ascending by description
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{sort}={descr}:{asc}'
                         .format(lb_id=lb_id, sort=const.SORT,
                                 descr=const.DESCRIPTION, asc=const.ASC))
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])
        self.assertEqual(listener3[const.DESCRIPTION],
                         listeners[2][const.DESCRIPTION])

        # Test fields
        show_listener_response_fields = const.SHOW_LISTENER_RESPONSE_FIELDS
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            show_listener_response_fields.append('timeout_client_data')
            show_listener_response_fields.append('timeout_member_connect')
            show_listener_response_fields.append('timeout_member_data')
            show_listener_response_fields.append('timeout_tcp_inspect')
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            show_listener_response_fields.append('allowed_cidrs')
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.27'):
            show_listener_response_fields.append(const.HSTS_PRELOAD)
            show_listener_response_fields.append(const.HSTS_MAX_AGE)
            show_listener_response_fields.append(const.HSTS_INCLUDE_SUBDOMAINS)
        for field in show_listener_response_fields:
            if field in (const.DEFAULT_POOL_ID, const.L7_POLICIES):
                continue
            listeners = self.mem_listener_client.list_listeners(
                query_params='loadbalancer_id={lb_id}&{fields}={field}'
                             .format(lb_id=lb_id,
                                     fields=const.FIELDS, field=field))
            self.assertEqual(1, len(listeners[0]))
            self.assertEqual(listener1[field], listeners[0][field])
            self.assertEqual(listener2[field], listeners[1][field])
            self.assertEqual(listener3[field], listeners[2][field])

        # Test multiple fields at the same time
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{fields}={admin}&'
                         '{fields}={created}'.format(
                             lb_id=lb_id, fields=const.FIELDS,
                             admin=const.ADMIN_STATE_UP,
                             created=const.CREATED_AT))
        self.assertEqual(2, len(listeners[0]))
        self.assertTrue(listeners[0][const.ADMIN_STATE_UP])
        parser.parse(listeners[0][const.CREATED_AT])
        self.assertTrue(listeners[1][const.ADMIN_STATE_UP])
        parser.parse(listeners[1][const.CREATED_AT])
        self.assertFalse(listeners[2][const.ADMIN_STATE_UP])
        parser.parse(listeners[2][const.CREATED_AT])

        # Test filtering
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{desc}={lb_desc}'.format(
                lb_id=lb_id, desc=const.DESCRIPTION,
                lb_desc=listener2[const.DESCRIPTION]))
        self.assertEqual(1, len(listeners))
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])

        # Test combined params
        listeners = self.mem_listener_client.list_listeners(
            query_params='loadbalancer_id={lb_id}&{admin}={true}&'
                         '{fields}={descr}&{fields}={id}&'
                         '{sort}={descr}:{desc}'.format(
                             lb_id=lb_id, admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, descr=const.DESCRIPTION,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        # Should get two listeners
        self.assertEqual(2, len(listeners))
        # listeners should have two fields
        self.assertEqual(2, len(listeners[0]))
        # Should be in descending order
        self.assertEqual(listener2[const.DESCRIPTION],
                         listeners[1][const.DESCRIPTION])
        self.assertEqual(listener1[const.DESCRIPTION],
                         listeners[0][const.DESCRIPTION])

        # Creating a list of 3 listeners, each one contains different tags
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            list_of_listeners = [listener1, listener2, listener3]
            test_list = []
            for listener in list_of_listeners:

                # If tags "English" and "Creativity" are in the listener's tags
                # and "Spanish" is not, add the listener to the list
                if "English" in listener[const.TAGS] and "Creativity" in (
                    listener[const.TAGS]) and "Spanish" not in (
                        listener[const.TAGS]):
                    test_list.append(listener[const.NAME])

            # Tests if only the first and the third ones have those tags
            self.assertEqual(
                test_list, [listener1[const.NAME], listener3[const.NAME]])

            # Tests that filtering by an empty tag will return an empty list
            self.assertTrue(not any(["" in listener[const.TAGS]
                                     for listener in list_of_listeners]))

    @decorators.idempotent_id('6e299eae-6907-4dfc-89c2-e57709d25d3d')
    def test_http_listener_show(self):
        self._test_listener_show(const.HTTP, 8050)

    @decorators.idempotent_id('aa838646-435f-4a20-8442-519a7a138e7e')
    def test_https_listener_show(self):
        self._test_listener_show(const.HTTPS, 8051)

    @decorators.idempotent_id('b851b754-4333-4115-9063-a9fce44c2e46')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.prometheus_listener_enabled,
        'PROMETHEUS listener tests are disabled in the tempest configuration.')
    def test_prometheus_listener_show(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.25'):
            raise self.skipException('PROMETHEUS listeners are only available '
                                     'on Octavia API version 2.25 or newer.')
        self._test_listener_show(const.PROMETHEUS, 8092)

    @decorators.idempotent_id('1fcbbee2-b697-4890-b6bf-d308ac1c94cd')
    def test_tcp_listener_show(self):
        self._test_listener_show(const.TCP, 8052)

    @decorators.idempotent_id('1dea3a6b-c95b-4e91-b591-1aa9cbcd0d1d')
    def test_udp_listener_show(self):
        self._test_listener_show(const.UDP, 8053)

    @decorators.idempotent_id('10992529-1d0a-47a3-855c-3dbcd868db4e')
    def test_sctp_listener_show(self):
        self._test_listener_show(const.SCTP, 8054)

    @decorators.idempotent_id('2c2e7146-0efc-44b6-8401-f1c69c2422fe')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_terminated_https_listener_show(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_show(const.TERMINATED_HTTPS, 8055)

    def _test_listener_show(self, protocol, protocol_port):
        """Tests listener show API.

        * Create a fully populated listener.
        * Show listener details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the listener.
        """
        self._validate_listener_protocol(protocol)

        listener_name = data_utils.rand_name("lb_member_listener1-show")
        listener_description = data_utils.arbitrary_string(size=255)
        hsts_supported = self.mem_listener_client.is_version_supported(
            self.api_version, '2.27') and protocol == const.TERMINATED_HTTPS

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            # const.DEFAULT_POOL_ID: '',
        }
        if protocol == const.HTTP:
            listener_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true",
                const.X_FORWARDED_PROTO: "true",
            }

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        if hsts_supported:
            listener_kwargs[const.HSTS_PRELOAD] = True
            listener_kwargs[const.HSTS_MAX_AGE] = 10000
            listener_kwargs[const.HSTS_INCLUDE_SUBDOMAINS] = True

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_tags = ["hello", "world"]
            listener_kwargs.update({
                const.TAGS: listener_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            listener_kwargs.update({const.ALLOWED_CIDRS: self.allowed_cidrs})

        listener = self.mem_listener_client.create_listener(**listener_kwargs)

        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)
        equal_items = [const.NAME, const.DESCRIPTION,
                       const.ADMIN_STATE_UP,
                       const.PROTOCOL, const.PROTOCOL_PORT,
                       const.CONNECTION_LIMIT]

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.TIMEOUT_CLIENT_DATA)
            equal_items.append(const.TIMEOUT_MEMBER_CONNECT)
            equal_items.append(const.TIMEOUT_MEMBER_DATA)
            equal_items.append(const.TIMEOUT_TCP_INSPECT)

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_kwargs[const.TAGS],
                                  listener[const.TAGS])

        for item in equal_items:
            self.assertEqual(listener_kwargs[item], listener[item])

        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            self.assertEqual(self.server_secret_ref,
                             listener[const.DEFAULT_TLS_CONTAINER_REF])
            self.assertEqual(sorted([self.SNI1_secret_ref,
                                     self.SNI2_secret_ref]),
                             sorted(listener[const.SNI_CONTAINER_REFS]))

        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            self.assertEqual(self.allowed_cidrs, listener[const.ALLOWED_CIDRS])

        if hsts_supported:
            self.assertTrue(listener[const.HSTS_PRELOAD])
            self.assertEqual(10000, listener[const.HSTS_MAX_AGE])
            self.assertTrue(listener[const.HSTS_INCLUDE_SUBDOMAINS])

        # Test that the appropriate users can see or not see the listener
        # based on the API RBAC.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_system_reader', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'ListenerClient', 'show_listener',
                expected_allowed, listener[const.ID])

    @decorators.idempotent_id('aaae0298-5778-4c7e-a27a-01549a71b319')
    def test_http_listener_update(self):
        self._test_listener_update(const.HTTP, 8060)

    @decorators.idempotent_id('9679b061-2b2c-469f-abd9-26ed140ef001')
    def test_https_listener_update(self):
        self._test_listener_update(const.HTTPS, 8061)

    @decorators.idempotent_id('cbba6bf8-9184-4da5-95e9-5efe1f89ddf0')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.prometheus_listener_enabled,
        'PROMETHEUS listener tests are disabled in the tempest configuration.')
    def test_prometheus_listener_update(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.25'):
            raise self.skipException('PROMETHEUS listeners are only available '
                                     'on Octavia API version 2.25 or newer.')
        self._test_listener_update(const.PROMETHEUS, 8093)

    @decorators.idempotent_id('8d933121-db03-4ccc-8b77-4e879064a9ba')
    def test_tcp_listener_update(self):
        self._test_listener_update(const.TCP, 8062)

    @decorators.idempotent_id('fd02dbfd-39ce-41c2-b181-54fc7ad91707')
    def test_udp_listener_update(self):
        self._test_listener_update(const.UDP, 8063)

    @decorators.idempotent_id('c590b485-4e08-4e49-b384-2282b3f6f1b9')
    def test_sctp_listener_update(self):
        self._test_listener_update(const.SCTP, 8064)

    @decorators.idempotent_id('2ae08e10-fbf8-46d8-a073-15f90454d718')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_terminated_https_listener_update(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_update(const.TERMINATED_HTTPS, 8065)

    def _test_listener_update(self, protocol, protocol_port):
        """Tests listener update and show APIs.

        * Create a fully populated listener.
        * Show listener details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the listener.
        * Update the listener details.
        * Show listener details.
        * Validate the show reflects the updated values.
        """
        self._validate_listener_protocol(protocol)

        listener_name = data_utils.rand_name("lb_member_listener1-update")
        listener_description = data_utils.arbitrary_string(size=255)
        hsts_supported = self.mem_listener_client.is_version_supported(
            self.api_version, '2.27') and protocol == const.TERMINATED_HTTPS

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: False,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
            # const.DEFAULT_POOL_ID: '',
        }
        if protocol == const.HTTP:
            listener_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "true",
                const.X_FORWARDED_PORT: "true",
                const.X_FORWARDED_PROTO: "true"
            }

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 1000,
                const.TIMEOUT_MEMBER_CONNECT: 1000,
                const.TIMEOUT_MEMBER_DATA: 1000,
                const.TIMEOUT_TCP_INSPECT: 50,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_tags = ["Hello", "World"]
            listener_kwargs.update({
                const.TAGS: listener_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            listener_kwargs.update({const.ALLOWED_CIDRS: self.allowed_cidrs})

        listener = self.mem_listener_client.create_listener(**listener_kwargs)

        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        self.assertEqual(listener_name, listener[const.NAME])
        self.assertEqual(listener_description, listener[const.DESCRIPTION])
        self.assertFalse(listener[const.ADMIN_STATE_UP])
        parser.parse(listener[const.CREATED_AT])
        parser.parse(listener[const.UPDATED_AT])
        UUID(listener[const.ID])
        # Operating status will be OFFLINE while admin_state_up = False
        self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        self.assertEqual(protocol, listener[const.PROTOCOL])
        self.assertEqual(protocol_port, listener[const.PROTOCOL_PORT])
        self.assertEqual(200, listener[const.CONNECTION_LIMIT])
        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertTrue(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))
        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            self.assertEqual(self.server_secret_ref,
                             listener[const.DEFAULT_TLS_CONTAINER_REF])
            self.assertEqual(sorted([self.SNI1_secret_ref,
                                     self.SNI2_secret_ref]),
                             sorted(listener[const.SNI_CONTAINER_REFS]))
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(1000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(1000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(50, listener[const.TIMEOUT_TCP_INSPECT])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_kwargs[const.TAGS],
                                  listener[const.TAGS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            self.assertEqual(self.allowed_cidrs, listener[const.ALLOWED_CIDRS])

        # Test that a user without the loadbalancer role cannot
        # update a listener.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'ListenerClient', 'update_listener',
                expected_allowed,
                status_method=self.mem_listener_client.show_listener,
                obj_id=listener[const.ID], listener_id=listener[const.ID],
                admin_state_up=True)

        new_name = data_utils.rand_name("lb_member_listener1-UPDATED")
        new_description = data_utils.arbitrary_string(size=255,
                                                      base_text='new')
        listener_update_kwargs = {
            const.NAME: new_name,
            const.DESCRIPTION: new_description,
            const.ADMIN_STATE_UP: True,
            const.CONNECTION_LIMIT: 400,
            # TODO(rm_work): need to finish the rest of this stuff
            # const.DEFAULT_POOL_ID: '',
        }
        if protocol == const.HTTP:
            listener_update_kwargs[const.INSERT_HEADERS] = {
                const.X_FORWARDED_FOR: "false",
                const.X_FORWARDED_PORT: "false",
                const.X_FORWARDED_PROTO: "false"
            }
        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener_update_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.SNI2_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.server_secret_ref],
            })
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            listener_update_kwargs.update({
                const.TIMEOUT_CLIENT_DATA: 2000,
                const.TIMEOUT_MEMBER_CONNECT: 2000,
                const.TIMEOUT_MEMBER_DATA: 2000,
                const.TIMEOUT_TCP_INSPECT: 100,
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            listener_updated_tags = ["Hola", "Mundo"]
            listener_update_kwargs.update({
                const.TAGS: listener_updated_tags
            })

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            # Test that CIDR IP version matches VIP IP version
            bad_cidrs = ['192.0.2.0/24', '2001:db8::/6']
            listener_update_kwargs.update({const.ALLOWED_CIDRS: bad_cidrs})
            self.assertRaises(
                exceptions.BadRequest,
                self.mem_listener_client.update_listener,
                listener[const.ID], **listener_update_kwargs)

            new_cidrs = ['192.0.2.0/24']
            if CONF.load_balancer.test_with_ipv6:
                new_cidrs = ['2001:db8::/64']
            listener_update_kwargs.update({const.ALLOWED_CIDRS: new_cidrs})

        if hsts_supported:
            listener_update_kwargs[const.HSTS_PRELOAD] = False
            listener_update_kwargs[const.HSTS_MAX_AGE] = 0
            listener_update_kwargs[const.HSTS_INCLUDE_SUBDOMAINS] = False

        listener = self.mem_listener_client.update_listener(
            listener[const.ID], **listener_update_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        self.assertEqual(new_name, listener[const.NAME])
        self.assertEqual(new_description, listener[const.DESCRIPTION])
        self.assertTrue(listener[const.ADMIN_STATE_UP])
        # Operating status is a measured status, so no-op will not go online
        if CONF.load_balancer.test_with_noop:
            self.assertEqual(const.OFFLINE, listener[const.OPERATING_STATUS])
        else:
            self.assertEqual(const.ONLINE, listener[const.OPERATING_STATUS])
        self.assertEqual(400, listener[const.CONNECTION_LIMIT])
        if protocol == const.HTTP:
            insert_headers = listener[const.INSERT_HEADERS]
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_FOR]))
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PORT]))
            self.assertFalse(strutils.bool_from_string(
                insert_headers[const.X_FORWARDED_PROTO]))
        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            self.assertEqual(self.SNI2_secret_ref,
                             listener[const.DEFAULT_TLS_CONTAINER_REF])
            self.assertEqual(sorted([self.SNI1_secret_ref,
                                     self.server_secret_ref]),
                             sorted(listener[const.SNI_CONTAINER_REFS]))
        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.1'):
            self.assertEqual(2000, listener[const.TIMEOUT_CLIENT_DATA])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_CONNECT])
            self.assertEqual(2000, listener[const.TIMEOUT_MEMBER_DATA])
            self.assertEqual(100, listener[const.TIMEOUT_TCP_INSPECT])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(listener_update_kwargs[const.TAGS],
                                  listener[const.TAGS])

        if self.mem_listener_client.is_version_supported(
                self.api_version, '2.12'):
            expected_cidrs = ['192.0.2.0/24']
            if CONF.load_balancer.test_with_ipv6:
                expected_cidrs = ['2001:db8::/64']
            self.assertEqual(expected_cidrs, listener[const.ALLOWED_CIDRS])

        if hsts_supported:
            self.assertFalse(listener[const.HSTS_PRELOAD])
            self.assertEqual(0, listener[const.HSTS_MAX_AGE])
            self.assertFalse(listener[const.HSTS_INCLUDE_SUBDOMAINS])

    @decorators.idempotent_id('16f11c82-f069-4592-8954-81b35a98e3b7')
    def test_http_listener_delete(self):
        self._test_listener_delete(const.HTTP, 8070)

    @decorators.idempotent_id('769526a0-df71-47cd-996e-46484de32223')
    def test_https_listener_delete(self):
        self._test_listener_delete(const.HTTPS, 8071)

    @decorators.idempotent_id('322a6372-6b56-4a3c-87e3-dd82074bc83e')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.prometheus_listener_enabled,
        'PROMETHEUS listener tests are disabled in the tempest configuration.')
    def test_prometheus_listener_delete(self):
        if not self.mem_listener_client.is_version_supported(
                self.api_version, '2.25'):
            raise self.skipException('PROMETHEUS listeners are only available '
                                     'on Octavia API version 2.25 or newer.')
        self._test_listener_delete(const.PROMETHEUS, 8094)

    @decorators.idempotent_id('f5ca019d-2b33-48f9-9c2d-2ec169b423ca')
    def test_tcp_listener_delete(self):
        self._test_listener_delete(const.TCP, 8072)

    @decorators.idempotent_id('86bd9717-e3e9-41e3-86c4-888c64455926')
    def test_udp_listener_delete(self):
        self._test_listener_delete(const.UDP, 8073)

    @decorators.idempotent_id('0de6f1ad-58ae-4b31-86b6-b440fce70244')
    def test_sctp_listener_delete(self):
        self._test_listener_delete(const.SCTP, 8074)

    @decorators.idempotent_id('ef357dcc-c9a0-40fe-a15c-b368f15d7187')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_terminated_https_listener_delete(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_delete(const.TERMINATED_HTTPS, 8075)

    def _test_listener_delete(self, protocol, protocol_port):
        """Tests listener create and delete APIs.

        * Creates a listener.
        * Validates that other accounts cannot delete the listener
        * Deletes the listener.
        * Validates the listener is in the DELETED state.
        """
        self._validate_listener_protocol(protocol)

        listener_name = data_utils.rand_name("lb_member_listener1-delete")

        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
        }

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        listener = self.mem_listener_client.create_listener(**listener_kwargs)

        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the loadbalancer role cannot
        # delete a listener.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'ListenerClient', 'delete_listener',
                expected_allowed,
                status_method=self.mem_listener_client.show_listener,
                obj_id=listener[const.ID], listener_id=listener[const.ID])

        self.mem_listener_client.delete_listener(listener[const.ID])

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_listener_client.show_listener, listener[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)

    @decorators.idempotent_id('6f14a6c1-945e-43bc-8215-410c8a5edb25')
    def test_http_listener_show_stats(self):
        self._test_listener_show_stats(const.HTTP, 8080)

    @decorators.idempotent_id('f8a43c27-f0a0-496d-a287-1958f337ac04')
    def test_https_listener_show_stats(self):
        self._test_listener_show_stats(const.HTTPS, 8081)

    @decorators.idempotent_id('8a999856-f448-498c-b891-21af449b5208')
    def test_tcp_listener_show_stats(self):
        self._test_listener_show_stats(const.TCP, 8082)

    @decorators.idempotent_id('a4c1f199-923b-41e4-a134-c91e590e20c4')
    def test_udp_listener_show_stats(self):
        self._test_listener_show_stats(const.UDP, 8083)

    @decorators.idempotent_id('7f6d3906-529c-4b99-8376-b836059df220')
    def test_sctp_listener_show_stats(self):
        self._test_listener_show_stats(const.SCTP, 8084)

    @decorators.idempotent_id('c39c996f-9633-4d81-a5f1-e94643f0c650')
    @testtools.skipUnless(
        CONF.loadbalancer_feature_enabled.terminated_tls_enabled,
        '[loadbalancer-feature-enabled] "terminated_tls_enabled" is '
        'False in the tempest configuration. TLS tests will be skipped.')
    def test_terminated_https_listener_show_stats(self):
        if not self.should_apply_terminated_https():
            raise self.skipException(
                f'Listener API tests with {const.TERMINATED_HTTPS} protocol'
                ' require the either the barbican service,or running in noop.')
        self._test_listener_show_stats(const.TERMINATED_HTTPS, 8085)

    def _test_listener_show_stats(self, protocol, protocol_port):
        """Tests listener show statistics API.

        * Create a listener.
        * Validates that other accounts cannot see the stats for the
        *   listener.
        * Show listener statistics.
        * Validate the show reflects the expected values.
        """
        self._validate_listener_protocol(protocol)

        listener_name = data_utils.rand_name("lb_member_listener1-stats")
        listener_description = data_utils.arbitrary_string(size=255)

        listener_kwargs = {
            const.NAME: listener_name,
            const.DESCRIPTION: listener_description,
            const.ADMIN_STATE_UP: True,
            const.PROTOCOL: protocol,
            const.PROTOCOL_PORT: protocol_port,
            const.LOADBALANCER_ID: self.lb_id,
            const.CONNECTION_LIMIT: 200,
        }

        # Add terminated_https args
        if self.should_apply_terminated_https(protocol=protocol):
            listener_kwargs.update({
                const.DEFAULT_TLS_CONTAINER_REF: self.server_secret_ref,
                const.SNI_CONTAINER_REFS: [self.SNI1_secret_ref,
                                           self.SNI2_secret_ref],
            })

        listener = self.mem_listener_client.create_listener(**listener_kwargs)
        self.addCleanup(
            self.mem_listener_client.cleanup_listener,
            listener[const.ID],
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        listener = waiters.wait_for_status(
            self.mem_listener_client.show_listener,
            listener[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        if not CONF.load_balancer.test_with_noop:
            listener = waiters.wait_for_status(
                self.mem_listener_client.show_listener,
                listener[const.ID], const.OPERATING_STATUS,
                const.ONLINE,
                CONF.load_balancer.build_interval,
                CONF.load_balancer.build_timeout)

        # Test that a user, without the load balancer member role, cannot
        # use this command
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            self.assertRaises(
                exceptions.Forbidden,
                self.listener_client.get_listener_stats,
                listener[const.ID])

        # Test that a different user, with the load balancer role, cannot see
        # the listener stats
        if not CONF.load_balancer.RBAC_test_type == const.NONE:
            member2_client = self.member2_listener_client
            self.assertRaises(exceptions.Forbidden,
                              member2_client.get_listener_stats,
                              listener[const.ID])

        stats = self.mem_listener_client.get_listener_stats(listener[const.ID])

        self.assertEqual(5, len(stats))
        self.assertEqual(0, stats[const.ACTIVE_CONNECTIONS])
        self.assertEqual(0, stats[const.BYTES_IN])
        self.assertEqual(0, stats[const.BYTES_OUT])
        self.assertEqual(0, stats[const.REQUEST_ERRORS])
        self.assertEqual(0, stats[const.TOTAL_CONNECTIONS])
