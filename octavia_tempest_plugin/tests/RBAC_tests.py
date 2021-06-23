# Copyright 2021 Red Hat, Inc. All rights reserved.
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

import copy

from oslo_log import log as logging
from tempest import config
from tempest.lib import exceptions
from tempest import test

from octavia_tempest_plugin.common import constants
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RBACTestsMixin(test.BaseTestCase):

    def _get_client_method(self, cred_obj, client_str, method_str):
        """Get requested method from registered clients in Tempest."""
        lb_clients = getattr(cred_obj, 'load_balancer_v2')
        client = getattr(lb_clients, client_str)
        client_obj = client()
        method = getattr(client_obj, method_str)
        return method

    def _check_allowed(self, client_str, method_str, allowed_list,
                       *args, **kwargs):
        """Test an API call allowed RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param allowed_list: The list of credentials expected to be
                             allowed.  Example: ['os_roles_lb_member'].
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """
        for cred in allowed_list:
            try:
                cred_obj = getattr(self, cred)
            except AttributeError:
                # TODO(johnsom) Remove once scoped tokens is the default.
                if ((cred == 'os_system_admin' or cred == 'os_system_reader')
                        and not CONF.enforce_scope.octavia):
                    LOG.info('Skipping %s allowed RBAC test because '
                             'enforce_scope.octavia is not True', cred)
                    continue
                else:
                    self.fail('Credential {} "expected_allowed" for RBAC '
                              'testing was not created by tempest '
                              'credentials setup. This is likely a bug in the '
                              'test.'.format(cred))
            method = self._get_client_method(cred_obj, client_str, method_str)
            try:
                method(*args, **kwargs)
            except exceptions.Forbidden as e:
                self.fail('Method {}.{} failed to allow access via RBAC using '
                          'credential {}. Error: {}'.format(
                              client_str, method_str, cred, str(e)))

    def _check_disallowed(self, client_str, method_str, allowed_list,
                          status_method=None, obj_id=None, *args, **kwargs):
        """Test an API call disallowed RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param allowed_list: The list of credentials expected to be
                             allowed.  Example: ['os_roles_lb_member'].
        :param status_method: The service client method that will provide
                              the object status for a status change waiter.
        :param obj_id: The ID of the object to check for the expected status
                       update.
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """
        expected_disallowed = (set(self.allocated_credentials) -
                               set(allowed_list))
        for cred in expected_disallowed:
            cred_obj = getattr(self, cred)
            method = self._get_client_method(cred_obj, client_str, method_str)

            # Unfortunately tempest uses testtools assertRaises[1] which means
            # we cannot use the unittest assertRaises context[2] with msg= to
            # give a useful error.
            # Also, testtools doesn't work with subTest[3], so we can't use
            # that to expose the failing credential.
            # This all means the exception raised testtools assertRaises
            # is less than useful.
            # TODO(johnsom) Remove this try block once testtools is useful.
            # [1] https://testtools.readthedocs.io/en/latest/
            #     api.html#testtools.TestCase.assertRaises
            # [2] https://docs.python.org/3/library/
            #     unittest.html#unittest.TestCase.assertRaises
            # [3] https://github.com/testing-cabal/testtools/issues/235
            try:
                method(*args, **kwargs)
            except exceptions.Forbidden:
                if status_method:
                    waiters.wait_for_status(
                        status_method, obj_id,
                        constants.PROVISIONING_STATUS, constants.ACTIVE,
                        CONF.load_balancer.check_interval,
                        CONF.load_balancer.check_timeout)

                continue
            self.fail('Method {}.{} failed to deny access via RBAC using '
                      'credential {}.'.format(client_str, method_str, cred))

    def _list_get_RBAC_enforcement(self, client_str, method_str,
                                   expected_allowed, *args, **kwargs):
        """Test an API call RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """

        allowed_list = copy.deepcopy(expected_allowed)
        # os_admin is a special case as it is valid with the old defaults,
        # but will not be with the new defaults and/or token scoping.
        # The old keystone role "admin" becomes project scoped "admin"
        # instead of being a global admin.
        # To keep the tests simple, handle that edge case here.
        # TODO(johnsom) Once token scope is default, remove this.
        if ('os_system_admin' in expected_allowed and
                not CONF.load_balancer.enforce_new_defaults and
                not CONF.enforce_scope.octavia):
            allowed_list.append('os_admin')

        # #### Test that disallowed credentials cannot access the API.
        self._check_disallowed(client_str, method_str, allowed_list,
                               None, None, *args, **kwargs)

        # #### Test that allowed credentials can access the API.
        self._check_allowed(client_str, method_str, allowed_list,
                            *args, **kwargs)

    def check_show_RBAC_enforcement(self, client_str, method_str,
                                    expected_allowed, *args, **kwargs):
        """Test an API show call RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """
        self._list_get_RBAC_enforcement(client_str, method_str,
                                        expected_allowed, *args, **kwargs)

    def check_list_RBAC_enforcement(self, client_str, method_str,
                                    expected_allowed, *args, **kwargs):
        """Test an API list call RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """
        self._list_get_RBAC_enforcement(client_str, method_str,
                                        expected_allowed, *args, **kwargs)

    def _CUD_RBAC_enforcement(self, client_str, method_str, expected_allowed,
                              status_method=None, obj_id=None,
                              *args, **kwargs):
        """Test an API create/update/delete call RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param status_method: The service client method that will provide
                              the object status for a status change waiter.
        :param obj_id: The ID of the object to check for the expected status
                       update.
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """

        allowed_list = copy.deepcopy(expected_allowed)
        # os_admin is a special case as it is valid with the old defaults,
        # but will not be with the new defaults and/or token scoping.
        # The old keystone role "admin" becomes project scoped "admin"
        # instead of being a global admin.
        # To keep the tests simple, handle that edge case here.
        # TODO(johnsom) Once token scope is default, remove this.
        if ('os_system_admin' in expected_allowed and
                not CONF.load_balancer.enforce_new_defaults and
                not CONF.enforce_scope.octavia):
            allowed_list.append('os_admin')

        # #### Test that disallowed credentials cannot access the API.
        self._check_disallowed(client_str, method_str, allowed_list,
                               status_method, obj_id, *args, **kwargs)

    def check_create_RBAC_enforcement(
            self, client_str, method_str, expected_allowed,
            status_method=None, obj_id=None, *args, **kwargs):
        """Test an API create call RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param status_method: The service client method that will provide
                              the object status for a status change waiter.
        :param obj_id: The ID of the object to check for the expected status
                       update.
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """
        self._CUD_RBAC_enforcement(client_str, method_str, expected_allowed,
                                   status_method, obj_id, *args, **kwargs)

    def check_delete_RBAC_enforcement(
            self, client_str, method_str, expected_allowed,
            status_method=None, obj_id=None, *args, **kwargs):
        """Test an API delete call RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param status_method: The service client method that will provide
                              the object status for a status change waiter.
        :param obj_id: The ID of the object to check for the expected status
                       update.
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """
        self._CUD_RBAC_enforcement(client_str, method_str, expected_allowed,
                                   status_method, obj_id, *args, **kwargs)

    def check_update_RBAC_enforcement(
            self, client_str, method_str, expected_allowed,
            status_method=None, obj_id=None, *args, **kwargs):
        """Test an API update call RBAC enforcement.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param status_method: The service client method that will provide
                              the object status for a status change waiter.
        :param obj_id: The ID of the object to check for the expected status
                       update.
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """
        self._CUD_RBAC_enforcement(client_str, method_str, expected_allowed,
                                   status_method, obj_id, *args, **kwargs)

    def check_list_RBAC_enforcement_count(
            self, client_str, method_str, expected_allowed, expected_count,
            *args, **kwargs):
        """Test an API list call RBAC enforcement result count.

        List APIs will return the object list for the project associated
        with the token used to access the API. This means most credentials
        will have access, but will get differing results.

        This test will query the list API using a list of credentials and
        will validate that only the expected count of results are returned.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param expected_count: The number of results expected in the list
                               returned from the API.
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """

        allowed_list = copy.deepcopy(expected_allowed)
        # os_admin is a special case as it is valid with the old defaults,
        # but will not be with the new defaults and/or token scoping.
        # The old keystone role "admin" becomes project scoped "admin"
        # instead of being a global admin.
        # To keep the tests simple, handle that edge case here.
        # TODO(johnsom) Once token scope is default, remove this.
        if ('os_system_admin' in expected_allowed and
                not CONF.load_balancer.enforce_new_defaults and
                not CONF.enforce_scope.octavia):
            allowed_list.append('os_admin')

        for cred in allowed_list:
            try:
                cred_obj = getattr(self, cred)
            except AttributeError:
                # TODO(johnsom) Remove once scoped tokens is the default.
                if ((cred == 'os_system_admin' or cred == 'os_system_reader')
                        and not CONF.enforce_scope.octavia):
                    LOG.info('Skipping %s allowed RBAC test because '
                             'enforce_scope.octavia is not True', cred)
                    continue
                else:
                    self.fail('Credential {} "expected_allowed" for RBAC '
                              'testing was not created by tempest '
                              'credentials setup. This is likely a bug in the '
                              'test.'.format(cred))
            method = self._get_client_method(cred_obj, client_str, method_str)
            try:
                result = method(*args, **kwargs)
            except exceptions.Forbidden as e:
                self.fail('Method {}.{} failed to allow access via RBAC using '
                          'credential {}. Error: {}'.format(
                              client_str, method_str, cred, str(e)))
            self.assertEqual(expected_count, len(result), message='Credential '
                             '{} saw {} objects when {} was expected.'.format(
                                 cred, len(result), expected_count))

    def check_list_IDs_RBAC_enforcement(
            self, client_str, method_str, expected_allowed, expected_ids,
            *args, **kwargs):
        """Test an API list call RBAC enforcement result contains IDs.

        List APIs will return the object list for the project associated
        with the token used to access the API. This means most credentials
        will have access, but will get differing results.

        This test will query the list API using a list of credentials and
        will validate that the expected object Ids in included in the results.

        :param client_str: The service client to use for the test, without the
                           credential.  Example: 'AmphoraClient'
        :param method_str: The method on the client to call for the test.
                           Example: 'list_amphorae'
        :param expected_allowed: The list of credentials expected to be
                                 allowed.  Example: ['os_roles_lb_member'].
        :param expected_ids: The list of object IDs to validate are included
                             in the returned list from the API.
        :param args: Any positional parameters needed by the method.
        :param kwargs: Any named parameters needed by the method.
        :raises AssertionError: Raised if the RBAC tests fail.
        :raises Forbidden: Raised if a credential that should have access does
                           not and is denied.
        :raises InvalidScope: Raised if a credential that should have the
                              correct scope for access is denied.
        :returns: None on success
        """

        allowed_list = copy.deepcopy(expected_allowed)
        # os_admin is a special case as it is valid with the old defaults,
        # but will not be with the new defaults and/or token scoping.
        # The old keystone role "admin" becomes project scoped "admin"
        # instead of being a global admin.
        # To keep the tests simple, handle that edge case here.
        # TODO(johnsom) Once token scope is default, remove this.
        if ('os_system_admin' in expected_allowed and
                not CONF.load_balancer.enforce_new_defaults and
                not CONF.enforce_scope.octavia):
            allowed_list.append('os_admin')

        for cred in allowed_list:
            try:
                cred_obj = getattr(self, cred)
            except AttributeError:
                # TODO(johnsom) Remove once scoped tokens is the default.
                if ((cred == 'os_system_admin' or cred == 'os_system_reader')
                        and not CONF.enforce_scope.octavia):
                    LOG.info('Skipping %s allowed RBAC test because '
                             'enforce_scope.octavia is not True', cred)
                    continue
                else:
                    self.fail('Credential {} "expected_allowed" for RBAC '
                              'testing was not created by tempest '
                              'credentials setup. This is likely a bug in the '
                              'test.'.format(cred))
            method = self._get_client_method(cred_obj, client_str, method_str)
            try:
                result = method(*args, **kwargs)
            except exceptions.Forbidden as e:
                self.fail('Method {}.{} failed to allow access via RBAC using '
                          'credential {}. Error: {}'.format(
                              client_str, method_str, cred, str(e)))
            result_ids = [lb[constants.ID] for lb in result]
            self.assertTrue(set(expected_ids).issubset(set(result_ids)))
