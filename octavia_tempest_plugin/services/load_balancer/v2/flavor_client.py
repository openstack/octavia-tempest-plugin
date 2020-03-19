#   Copyright 2019 Rackspace US Inc.  All rights reserved.
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
from tempest.lib import exceptions

from octavia_tempest_plugin.common.decorators import skip_if_not_implemented
from octavia_tempest_plugin.services.load_balancer.v2 import base_client

LOG = logging.getLogger(__name__)
Unset = base_client.Unset


class FlavorClient(base_client.BaseLBaaSClient):

    root_tag = 'flavor'
    list_root_tag = 'flavors'

    @skip_if_not_implemented
    def create_flavor(self, name, flavor_profile_id, description=Unset,
                      enabled=Unset, return_object_only=True):
        """Create a flavor.

        :param name: Human-readable name of the resource.
        :param flavor_profile_id: The ID of the associated flavor profile.
        :param description: A human-readable description for the resource.
        :param enabled: If the resource is available for use.
                        The default is True.
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
        :returns: A flavor object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        return self._create_object(**kwargs)

    @skip_if_not_implemented
    def show_flavor(self, flavor_id, query_params=None,
                    return_object_only=True):
        """Get the flavor details.

        :param flavor_id: The flavor ID to query.
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
        :returns: A flavor object.
        """
        return self._show_object(obj_id=flavor_id,
                                 query_params=query_params,
                                 return_object_only=return_object_only)

    @skip_if_not_implemented
    def list_flavors(self, query_params=None, return_object_only=True):
        """Get a list of flavor objects.

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
        :returns: A list of flavor objects.
        """
        return self._list_objects(query_params=query_params,
                                  return_object_only=return_object_only)

    @skip_if_not_implemented
    def update_flavor(self, flavor_id, name=Unset, description=Unset,
                      enabled=Unset, return_object_only=True):
        """Update a flavor.

        :param flavor_id: The flavor ID to update.
        :param name: Human-readable name of the resource.
        :param description: A human-readable description for the resource.
        :param enabled: If the resource is available for use.
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
        :returns: A flavor object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('flavor_id')
        return self._update_object(**kwargs)

    @skip_if_not_implemented
    def delete_flavor(self, flavor_id, ignore_errors=False):
        """Delete a flavor.

        :param flavor_id: The flavor ID to delete.
        :param ignore_errors: True if errors should be ignored.
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
        return self._delete_obj(obj_id=flavor_id, ignore_errors=ignore_errors)

    def cleanup_a_flavor(self, flavor_id):
        """Delete a flavor for tempest cleanup.

           We cannot use the cleanup_flavor method as flavors
           do not have a provisioning_status.

        :param flavor_id: The flavor ID to delete.
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
        try:
            self._delete_obj(obj_id=flavor_id)
        except exceptions.NotFound:
            # Already gone, cleanup complete
            LOG.info("Flavor %s is already gone. "
                     "Cleanup considered complete.", flavor_id)
