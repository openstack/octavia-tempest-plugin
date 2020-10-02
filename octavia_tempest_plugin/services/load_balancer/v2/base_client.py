#   Copyright 2018 GoDaddy
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
#

from oslo_log import log as logging
from oslo_serialization import jsonutils
from tempest import config
from tempest.lib.common import rest_client
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF
LOG = logging.getLogger(__name__)


class Unset(object):
    def __bool__(self):
        return False

    __nonzero__ = __bool__

    def __repr__(self):
        return 'Unset'


class BaseLBaaSClient(rest_client.RestClient):

    root_tag = None
    list_root_tag = None
    base_uri = '/v2.0/lbaas/{object}'

    def __init__(self, auth_provider, service, region, **kwargs):
        super(BaseLBaaSClient, self).__init__(auth_provider, service,
                                              region, **kwargs)
        self.timeout = CONF.load_balancer.build_timeout
        self.build_interval = CONF.load_balancer.build_interval
        self.uri = self.base_uri.format(object=self.list_root_tag)
        # Create a method for each object's cleanup
        # This method should be used (rather than delete) for tempest cleanups.
        cleanup_func_name = 'cleanup_{}'.format(self.root_tag)
        if not hasattr(self, cleanup_func_name):
            setattr(self, cleanup_func_name, self._cleanup_obj)

    def _create_object(self, parent_id=None, return_object_only=True,
                       **kwargs):
        """Create an object.

        :param return_object_only: If True, the response returns the object
                                   inside the root tag. False returns the full
                                   response from the API.
        :param **kwargs: All attributes of the object should be passed as
                         keyword arguments to this function.
        :raises AssertionError: if the expected_code isn't a valid http success
                                response code
        :raises BadRequest: If a 400 response code is received
        :raises Conflict: If a 409 response code is received
        :raises Forbidden: If a 403 response code is received
        :raises Gone: If a 410 response code is received
        :raises InvalidContentType: If a 415 response code is received
        :raises InvalidHTTPResponseBody: The response body wasn't valid JSON
        :raises InvalidHttpSuccessCode: if the read code isn't an expected
                                        http success code
        :raises NotFound: If a 404 response code is received
        :raises NotImplemented: If a 501 response code is received
        :raises OverLimit: If a 413 response code is received and over_limit is
                           not in the response body
        :raises RateLimitExceeded: If a 413 response code is received and
                                   over_limit is in the response body
        :raises ServerFault: If a 500 response code is received
        :raises Unauthorized: If a 401 response code is received
        :raises UnexpectedContentType: If the content-type of the response
                                       isn't an expect type
        :raises UnexpectedResponseCode: If a response code above 400 is
                                        received and it doesn't fall into any
                                        of the handled checks
        :raises UnprocessableEntity: If a 422 response code is received and
                                     couldn't be parsed
        :returns: An appropriate object.
        """
        obj_dict = {self.root_tag: kwargs}

        if parent_id:
            request_uri = self.uri.format(parent=parent_id)
        else:
            request_uri = self.uri

        response, body = self.post(request_uri, jsonutils.dumps(obj_dict))
        self.expected_success(201, response.status)
        if return_object_only:
            return jsonutils.loads(body.decode('utf-8'))[self.root_tag]
        else:
            return jsonutils.loads(body.decode('utf-8'))

    def _show_object(self, obj_id, parent_id=None, query_params=None,
                     return_object_only=True):
        """Get object details.

        :param obj_id: The object ID to query.
        :param query_params: The optional query parameters to append to the
                             request. Ex. fields=id&fields=name
        :param return_object_only: If True, the response returns the object
                                   inside the root tag. False returns the full
                                   response from the API.
        :raises AssertionError: if the expected_code isn't a valid http success
                                response code
        :raises BadRequest: If a 400 response code is received
        :raises Conflict: If a 409 response code is received
        :raises Forbidden: If a 403 response code is received
        :raises Gone: If a 410 response code is received
        :raises InvalidContentType: If a 415 response code is received
        :raises InvalidHTTPResponseBody: The response body wasn't valid JSON
        :raises InvalidHttpSuccessCode: if the read code isn't an expected
                                        http success code
        :raises NotFound: If a 404 response code is received
        :raises NotImplemented: If a 501 response code is received
        :raises OverLimit: If a 413 response code is received and over_limit is
                           not in the response body
        :raises RateLimitExceeded: If a 413 response code is received and
                                   over_limit is in the response body
        :raises ServerFault: If a 500 response code is received
        :raises Unauthorized: If a 401 response code is received
        :raises UnexpectedContentType: If the content-type of the response
                                       isn't an expect type
        :raises UnexpectedResponseCode: If a response code above 400 is
                                        received and it doesn't fall into any
                                        of the handled checks
        :raises UnprocessableEntity: If a 422 response code is received and
                                     couldn't be parsed
        :returns: An appropriate object.
        """
        if parent_id:
            uri = self.uri.format(parent=parent_id)
        else:
            uri = self.uri

        if query_params:
            request_uri = '{0}/{1}?{2}'.format(uri, obj_id, query_params)
        else:
            request_uri = '{0}/{1}'.format(uri, obj_id)

        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return jsonutils.loads(body.decode('utf-8'))[self.root_tag]
        else:
            return jsonutils.loads(body.decode('utf-8'))

    def _list_objects(self, parent_id=None, query_params=None,
                      return_object_only=True):
        """Get a list of the appropriate objects.

        :param query_params: The optional query parameters to append to the
                             request. Ex. fields=id&fields=name
        :param return_object_only: If True, the response returns the object
                                   inside the root tag. False returns the full
                                   response from the API.
        :raises AssertionError: if the expected_code isn't a valid http success
                                response code
        :raises BadRequest: If a 400 response code is received
        :raises Conflict: If a 409 response code is received
        :raises Forbidden: If a 403 response code is received
        :raises Gone: If a 410 response code is received
        :raises InvalidContentType: If a 415 response code is received
        :raises InvalidHTTPResponseBody: The response body wasn't valid JSON
        :raises InvalidHttpSuccessCode: if the read code isn't an expected
                                        http success code
        :raises NotFound: If a 404 response code is received
        :raises NotImplemented: If a 501 response code is received
        :raises OverLimit: If a 413 response code is received and over_limit is
                           not in the response body
        :raises RateLimitExceeded: If a 413 response code is received and
                                   over_limit is in the response body
        :raises ServerFault: If a 500 response code is received
        :raises Unauthorized: If a 401 response code is received
        :raises UnexpectedContentType: If the content-type of the response
                                       isn't an expect type
        :raises UnexpectedResponseCode: If a response code above 400 is
                                        received and it doesn't fall into any
                                        of the handled checks
        :raises UnprocessableEntity: If a 422 response code is received and
                                     couldn't be parsed
        :returns: A list of appropriate objects.
        """
        if parent_id:
            uri = self.uri.format(parent=parent_id)
        else:
            uri = self.uri

        if query_params:
            request_uri = '{0}?{1}'.format(uri, query_params)
        else:
            request_uri = uri
        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return jsonutils.loads(body.decode('utf-8'))[self.list_root_tag]
        else:
            return jsonutils.loads(body.decode('utf-8'))

    def _update_object(self, obj_id, parent_id=None, return_object_only=True,
                       **kwargs):
        """Update an object.

        :param obj_id: The object ID to update.
        :param parent_id: The parent object ID, if applicable.
        :param return_object_only: If True, the response returns the object
                                   inside the root tag. False returns the full
                                   response from the API.
        :param **kwargs: All attributes of the object should be passed as
                         keyword arguments to this function.
        :raises AssertionError: if the expected_code isn't a valid http success
                                response code
        :raises BadRequest: If a 400 response code is received
        :raises Conflict: If a 409 response code is received
        :raises Forbidden: If a 403 response code is received
        :raises Gone: If a 410 response code is received
        :raises InvalidContentType: If a 415 response code is received
        :raises InvalidHTTPResponseBody: The response body wasn't valid JSON
        :raises InvalidHttpSuccessCode: if the read code isn't an expected
                                        http success code
        :raises NotFound: If a 404 response code is received
        :raises NotImplemented: If a 501 response code is received
        :raises OverLimit: If a 413 response code is received and over_limit is
                           not in the response body
        :raises RateLimitExceeded: If a 413 response code is received and
                                   over_limit is in the response body
        :raises ServerFault: If a 500 response code is received
        :raises Unauthorized: If a 401 response code is received
        :raises UnexpectedContentType: If the content-type of the response
                                       isn't an expect type
        :raises UnexpectedResponseCode: If a response code above 400 is
                                        received and it doesn't fall into any
                                        of the handled checks
        :raises UnprocessableEntity: If a 422 response code is received and
                                     couldn't be parsed
        :returns: An appropriate object.
        """
        obj_dict = {self.root_tag: kwargs}

        if parent_id:
            uri = self.uri.format(parent=parent_id)
        else:
            uri = self.uri

        request_uri = '{0}/{1}'.format(uri, obj_id)
        response, body = self.put(request_uri, jsonutils.dumps(obj_dict))
        self.expected_success(200, response.status)
        if return_object_only:
            return jsonutils.loads(body.decode('utf-8'))[self.root_tag]
        else:
            return jsonutils.loads(body.decode('utf-8'))

    def _delete_obj(self, obj_id, parent_id=None, ignore_errors=False,
                    cascade=False):
        """Delete an object.

        :param obj_id: The object ID to delete.
        :param ignore_errors: True if errors should be ignored.
        :param cascade: If true will delete all child objects of an
                        object, if that object supports it.
        :raises AssertionError: if the expected_code isn't a valid http success
                                response code
        :raises BadRequest: If a 400 response code is received
        :raises Conflict: If a 409 response code is received
        :raises Forbidden: If a 403 response code is received
        :raises Gone: If a 410 response code is received
        :raises InvalidContentType: If a 415 response code is received
        :raises InvalidHTTPResponseBody: The response body wasn't valid JSON
        :raises InvalidHttpSuccessCode: if the read code isn't an expected
                                        http success code
        :raises NotFound: If a 404 response code is received
        :raises NotImplemented: If a 501 response code is received
        :raises OverLimit: If a 413 response code is received and over_limit is
                           not in the response body
        :raises RateLimitExceeded: If a 413 response code is received and
                                   over_limit is in the response body
        :raises ServerFault: If a 500 response code is received
        :raises Unauthorized: If a 401 response code is received
        :raises UnexpectedContentType: If the content-type of the response
                                       isn't an expect type
        :raises UnexpectedResponseCode: If a response code above 400 is
                                        received and it doesn't fall into any
                                        of the handled checks
        :raises UnprocessableEntity: If a 422 response code is received and
                                     couldn't be parsed
        :returns: None if ignore_errors is True, the response status code
                  if not.
        """
        if parent_id:
            uri = self.uri.format(parent=parent_id)
        else:
            uri = self.uri

        if cascade:
            request_uri = '{0}/{1}?cascade=true'.format(uri, obj_id)
        else:
            request_uri = '{0}/{1}'.format(uri, obj_id)
        if ignore_errors:
            try:
                response, body = self.delete(request_uri)
            except Exception:
                return
        else:
            response, body = self.delete(request_uri)

        self.expected_success(204, response.status)
        return response.status

    def _cleanup_obj(self, obj_id, lb_client=None, lb_id=None, parent_id=None,
                     cascade=False):
        """Clean up an object (for use in tempest addClassResourceCleanup).

        We always need to wait for the parent LB to be in a mutable state
        before deleting the child object, and the cleanups will not guarantee
        this if we just pass the delete function to tempest cleanup.
        For example, if we add multiple listeners on the same LB to cleanup,
        tempest will delete the first one and then immediately try to delete
        the second one, which will fail because the LB will be immutable.

        We also need to wait to return until the parent LB is back in a mutable
        state so future tests don't break right at the start.

        This function:
        * Waits until the parent LB is ACTIVE
        * Deletes the object
        * Waits until the parent LB is ACTIVE

        :param obj_id: The object ID to clean up.
        :param lb_client: (Optional) The loadbalancer client, if this isn't the
                          loadbalancer client already.
        :param lb_id: (Optional) The ID of the parent loadbalancer, if the main
                      obj_id is for a sub-object and not a loadbalancer.
        :param cascade: If true will delete all child objects of an
                        object, if that object supports it.
        :return:
        """
        if parent_id:
            uri = self.uri.format(parent=parent_id)
        else:
            uri = self.uri

        if lb_client and lb_id:
            wait_id = lb_id
            wait_client = lb_client
            wait_func = lb_client.show_loadbalancer
        else:
            wait_id = obj_id
            wait_client = self
            wait_func = self._show_object

        LOG.info("Starting cleanup for %s %s...", self.root_tag, obj_id)

        try:
            request_uri = '{0}/{1}'.format(uri, obj_id)
            response, body = self.get(request_uri)
            resp_obj = jsonutils.loads(body.decode('utf-8'))[self.root_tag]
            if (response.status == 404 or
                    resp_obj['provisioning_status'] == const.DELETED):
                raise exceptions.NotFound()
        except exceptions.NotFound:
            # Already gone, cleanup complete
            LOG.info("%s %s is already gone. Cleanup considered complete.",
                     self.root_tag, obj_id)
            return

        LOG.info("Waiting for %s %s to be ACTIVE...",
                 wait_client.root_tag, wait_id)
        try:
            waiters.wait_for_status(wait_func, wait_id,
                                    const.PROVISIONING_STATUS,
                                    const.ACTIVE,
                                    CONF.load_balancer.check_interval,
                                    CONF.load_balancer.check_timeout)
        except exceptions.UnexpectedResponseCode:
            # Status is ERROR, go ahead with deletion
            LOG.debug("Found %s %s in ERROR status, proceeding with cleanup.",
                      wait_client.root_tag, wait_id)
        except exceptions.TimeoutException:
            # Timed out, nothing to be done, let errors happen
            LOG.error("Timeout exceeded waiting to clean up %s %s.",
                      self.root_tag, obj_id)
        except exceptions.NotFound:
            # Already gone, cleanup complete
            LOG.info("%s %s is already gone. Cleanup considered complete.",
                     wait_client.root_tag.capitalize(), wait_id)
            return
        except Exception as e:
            # Log that something weird happens, then let the chips fall
            LOG.error("Cleanup encountered an unknown exception while waiting "
                      "for %s %s: %s", wait_client.root_tag, wait_id, e)

        if cascade:
            uri = '{0}/{1}?cascade=true'.format(uri, obj_id)
        else:
            uri = '{0}/{1}'.format(uri, obj_id)
        LOG.info("Cleaning up %s %s...", self.root_tag, obj_id)
        return_status = test_utils.call_and_ignore_notfound_exc(
            self.delete, uri)

        if lb_id and lb_client:
            LOG.info("Waiting for %s %s to be ACTIVE...",
                     wait_client.root_tag, wait_id)
            waiters.wait_for_status(wait_func, wait_id,
                                    const.PROVISIONING_STATUS,
                                    const.ACTIVE,
                                    CONF.load_balancer.check_interval,
                                    CONF.load_balancer.check_timeout)
        else:
            LOG.info("Waiting for %s %s to be DELETED...",
                     wait_client.root_tag, wait_id)
            waiters.wait_for_deleted_status_or_not_found(
                wait_func, wait_id, const.PROVISIONING_STATUS,
                CONF.load_balancer.check_interval,
                CONF.load_balancer.check_timeout)

        LOG.info("Cleanup complete for %s %s...", self.root_tag, obj_id)
        return return_status

    def is_resource_deleted(self, id):
        """Check if the object is deleted.

        :param id: The object ID to check.
        :return: boolean state representing the object's deleted state
        """
        try:
            obj = self._show_object(id)
            if obj.get(const.PROVISIONING_STATUS) == const.DELETED:
                return True
        except exceptions.NotFound:
            return True
        return False

    def get_max_api_version(self):
        """Get the maximum version available on the API endpoint.

        :return: Maximum version string available on the endpoint.
        """
        response, body = self.get('/')
        self.expected_success(200, response.status)

        versions_list = jsonutils.loads(body.decode('utf-8'))['versions']
        current_versions = (version for version in versions_list if
                            version['status'] == 'CURRENT')
        max_version = '0.0'
        for version in current_versions:

            ver_string = version['id']
            if ver_string.startswith("v"):
                ver_string = ver_string[1:]

            ver_split = list(map(int, ver_string.split('.')))
            max_split = list(map(int, max_version.split('.')))

            if len(ver_split) > 2:
                raise exceptions.InvalidAPIVersionString(version=ver_string)

            if ver_split[0] > max_split[0] or (
                    ver_split[0] == max_split[0] and
                    ver_split[1] >= max_split[1]):
                max_version = ver_string

        if max_version == '0.0':
            raise exceptions.InvalidAPIVersionString(version=max_version)

        return max_version

    def is_version_supported(self, api_version, version):
        """Check if a version is supported by the API.

        :param api_version: Reference endpoint API version.
        :param version: Version to check against API version.
        :return: boolean if the version is supported.
        """

        api_split = list(map(int, api_version.split('.')))
        ver_split = list(map(int, version.split('.')))

        if api_split[0] > ver_split[0] or (
                api_split[0] == ver_split[0] and api_split[1] >= ver_split[1]):
            return True
        return False
