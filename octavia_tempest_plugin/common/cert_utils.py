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

import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.x509.oid import NameOID
import OpenSSL


def generate_ca_cert_and_key():
    """Creates a CA cert and key for testing.

    :returns: The cryptography CA cert and CA key objects.
    """

    ca_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Denial"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Corvallis"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OpenStack"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Octavia"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ca_cert.example.com"),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"ca_cert.example.com")]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        # KeyUsage(digital_signature, content_commitment, key_encipherment,
        #          data_encipherment, key_agreement, key_cert_sign, crl_sign,
        #          encipher_only, decipher_only)
        x509.KeyUsage(True, False, False, False, False,
                      True, True, False, False),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    return ca_cert, ca_key


def generate_server_cert_and_key(ca_cert, ca_key, server_uuid):
    """Creates a server cert and key for testing.

    :param ca_cert: A cryptography CA certificate (x509) object.
    :param ca_key: A cryptography CA key (x509) object.
    :param server_uuid: A UUID identifying the server.
    :returns: The cryptography server cert and key objects.
    """

    server_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Denial"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Corvallis"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OpenStack"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Octavia"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"{}.example.com".format(
            server_uuid)),
    ])

    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(u"{}.example.com".format(server_uuid))]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        # KeyUsage(digital_signature, content_commitment, key_encipherment,
        #          data_encipherment, key_agreement, key_cert_sign, crl_sign,
        #          encipher_only, decipher_only)
        x509.KeyUsage(True, False, True, False, False,
                      False, False, False, False),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    return server_cert, server_key


def generate_client_cert_and_key(ca_cert, ca_key, client_uuid):
    """Creates a client cert and key for testing.

    :param ca_cert: A cryptography CA certificate (x509) object.
    :param ca_key: A cryptography CA key (x509) object.
    :param client_uuid: A UUID identifying the client.
    :returns: The cryptography server cert and key objects.
    """

    client_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Denial"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Corvallis"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OpenStack"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Octavia"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(client_uuid)),
    ])

    client_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        client_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        # KeyUsage(digital_signature, content_commitment, key_encipherment,
        #          data_encipherment, key_agreement, key_cert_sign, crl_sign,
        #          encipher_only, decipher_only)
        x509.KeyUsage(True, True, True, False, False, False,
                      False, False, False),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    return client_cert, client_key


def generate_pkcs12_bundle(server_cert, server_key):
    """Creates a pkcs12 formated bundle.

    Note: This uses pyOpenSSL as the cryptography package does not yet
          support creating pkcs12 bundles. The currently un-released
          2.5 version of cryptography supports reading pkcs12, but not
          creation. This method should be updated to only use
          cryptography once it supports creating pkcs12 bundles.

    :param server_cert: A cryptography certificate (x509) object.
    :param server_key: A cryptography key (x509) object.
    :returns: A pkcs12 bundle.
    """
    # Use the PKCS12 serialization function from cryptography if it exists
    # (>=3.0), otherwise use the pyOpenSSL module.
    #
    # The PKCS12 class of the pyOpenSSL module is not compliant with FIPS.
    # It uses the SHA1 function [0] which is not allowed when generating
    # digital signatures [1]
    #
    # [0] https://github.com/pyca/pyopenssl/blob/
    #       65ca53a7a06a7c78c1749200a6b3a007e47d3214/src/OpenSSL/
    #       crypto.py#L2748-L2749
    # [1] https://nvlpubs.nist.gov/nistpubs/SpecialPublications/
    #       NIST.SP.800-131Ar1.pdf
    if hasattr(pkcs12, 'serialize_key_and_certificates'):
        p12 = pkcs12.serialize_key_and_certificates(
            b'', server_key, server_cert,
            cas=None, encryption_algorithm=NoEncryption())
    else:
        p12 = OpenSSL.crypto.PKCS12()
        p12.set_privatekey(
            OpenSSL.crypto.PKey.from_cryptography_key(server_key))
        p12.set_certificate(OpenSSL.crypto.X509.from_cryptography(server_cert))
        p12 = p12.export()
    return p12


def generate_certificate_revocation_list(ca_cert, ca_key, cert_to_revoke):
    """Create a certificate revocation list with a revoked certificate.

    :param ca_cert: A cryptography CA certificate (x509) object.
    :param ca_key: A cryptography CA key (x509) object.
    :param cert_to_revoke: A cryptography CA certificate (x509) object.
    :returns: A signed certificate revocation list.
    """
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_cert.subject)
    crl_builder = crl_builder.last_update(datetime.datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.datetime.utcnow() +
                                          datetime.timedelta(1, 0, 0))

    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        cert_to_revoke.serial_number
    ).revocation_date(
        datetime.datetime.utcnow()
    ).build(default_backend())

    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
    return crl_builder.sign(private_key=ca_key, algorithm=hashes.SHA256(),
                            backend=default_backend())
