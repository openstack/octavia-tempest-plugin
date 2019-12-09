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

from barbicanclient import client
from keystoneauth1 import identity
from keystoneauth1 import session
from oslo_log import log as logging
from tempest.lib.common.utils import data_utils

LOG = logging.getLogger(__name__)


class BarbicanClientManager(object):
    """Class for interacting with the barbican service.

    This class is an abstraction for interacting with the barbican service.
    This class currently uses the barbican client code to access barbican due
    to the following reasons:
    1. Octavia users typically load secrets into barbican via the client.
    2. The barbican-tempest-plugin is lightly tested (no py3 tests, etc.).
    3. barbican-tempest-plugin is not in global requirements.

    This led to the decision to not use the service client in the
    barbican-tempest-plugin.

    In the future it may be better to use the barbican-tempest-plugin
    service client or the openstacksdk.
    """

    def __init__(self, tempest_client_mgr):
        """Setup the barbican client.

        :param tempest_client_mgr: A tempest client manager object, such as
                                   os_primary.
        """
        # Convert the tempest credential passed in into a keystone session
        auth_provider = tempest_client_mgr.auth_provider
        cert_validation = False
        if not auth_provider.dscv:
            cert_validation = auth_provider.ca_certs
        credentials = tempest_client_mgr.credentials
        keystone_auth = identity.v3.Token(
            auth_url=auth_provider.auth_url,
            token=auth_provider.get_token(),
            project_id=credentials.project_id,
            project_name=credentials.project_name,
            project_domain_id=credentials.project_domain_id,
            project_domain_name=credentials.project_domain_name)
        id_session = session.Session(auth=keystone_auth,
                                     verify=cert_validation)

        # Setup the barbican client
        self.barbican = client.Client(session=id_session)

    def store_secret(self, secret):
        """Store a secret in barbican.

        :param secret: A pkcs12 secret.
        :returns: The barbican secret_ref.
        """
        p12_secret = self.barbican.secrets.create()
        p12_secret.name = data_utils.rand_name("lb_member_barbican")
        p12_secret.payload = secret
        secret_ref = p12_secret.store()
        LOG.debug('Secret {0} has ref {1}'.format(p12_secret.name, secret_ref))
        return secret_ref

    def delete_secret(self, secret_ref):
        self.barbican.secrets.delete(secret_ref)

    def add_acl(self, secret_ref, user_id):
        acl_entity = self.barbican.acls.create(entity_ref=secret_ref,
                                               users=[user_id],
                                               project_access=True)
        acl_ref = acl_entity.submit()
        LOG.debug('Secret ACL {0} added user {1}'.format(acl_ref, user_id))
        return acl_ref
