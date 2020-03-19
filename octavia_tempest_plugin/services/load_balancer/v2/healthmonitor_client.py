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

from tempest import config

from octavia_tempest_plugin.common.decorators import skip_if_not_implemented
from octavia_tempest_plugin.services.load_balancer.v2 import base_client

CONF = config.CONF
Unset = base_client.Unset


class HealthMonitorClient(base_client.BaseLBaaSClient):

    root_tag = 'healthmonitor'
    list_root_tag = 'healthmonitors'
    resource_name = 'healthmonitor'

    @skip_if_not_implemented
    def create_healthmonitor(self, pool_id, type, delay, timeout, max_retries,
                             max_retries_down=Unset, name=Unset, tags=Unset,
                             http_method=Unset, url_path=Unset,
                             expected_codes=Unset, admin_state_up=Unset,
                             return_object_only=True):
        """Create a healthmonitor.

        :param pool_id: The ID of the pool.
        :param type: The type of health monitor.
        :param delay: The time, in seconds, between sending probes to members.
        :param timeout: The maximum time, in seconds, that a monitor waits to
                        connect before it times out.
        :param max_retries: The number of successful checks before changing the
                            operating status of the member to ONLINE.
        :param max_retries_down: The number of allowed check failures before
                                 changing the operating status of the member to
                                 ERROR.
        :param name: Human-readable name of the resource.
        :param tags: Human-readable tags of the resource.
        :param http_method: The HTTP method that the health monitor uses for
                            requests.
        :param url_path: The HTTP URL path of the request sent by the monitor
                         to test the health of a backend member.
        :param expected_codes: The list of HTTP status codes expected in
                               response from the member to declare it healthy.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
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
        :returns: A healthmonitor object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        return self._create_object(**kwargs)

    @skip_if_not_implemented
    def show_healthmonitor(self, healthmonitor_id, query_params=None,
                           return_object_only=True):
        """Get healthmonitor details.

        :param healthmonitor_id: The healthmonitor ID to query.
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
        :returns: A healthmonitor object.
        """
        return self._show_object(obj_id=healthmonitor_id,
                                 query_params=query_params,
                                 return_object_only=return_object_only)

    @skip_if_not_implemented
    def list_healthmonitors(self, query_params=None, return_object_only=True):
        """Get a list of healthmonitor objects.

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
        :returns: A list of healthmonitor objects.
        """
        return self._list_objects(query_params=query_params,
                                  return_object_only=return_object_only)

    @skip_if_not_implemented
    def update_healthmonitor(self, healthmonitor_id, delay=Unset,
                             timeout=Unset, max_retries=Unset,
                             max_retries_down=Unset, name=Unset, tags=Unset,
                             http_method=Unset, url_path=Unset,
                             expected_codes=Unset, admin_state_up=Unset,
                             return_object_only=True):
        """Update a healthmonitor.

        :param healthmonitor_id: The healthmonitor ID to update.
        :param delay: The time, in seconds, between sending probes to members.
        :param timeout: The maximum time, in seconds, that a monitor waits to
                        connect before it times out.
        :param max_retries: The number of successful checks before changing the
                            operating status of the member to ONLINE.
        :param max_retries_down: The number of allowed check failures before
                                 changing the operating status of the member to
                                 ERROR.
        :param name: Human-readable name of the resource.
        :param tags: Human-readable tags of the resource.
        :param http_method: The HTTP method that the health monitor uses for
                            requests.
        :param url_path: The HTTP URL path of the request sent by the monitor
                         to test the health of a backend member.
        :param expected_codes: The list of HTTP status codes expected in
                               response from the member to declare it healthy.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
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
        :returns: A healthmonitor object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('healthmonitor_id')
        return self._update_object(**kwargs)

    @skip_if_not_implemented
    def delete_healthmonitor(self, healthmonitor_id, ignore_errors=False):
        """Delete a healthmonitor.

        :param healthmonitor_id: The healthmonitor ID to delete.
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
        return self._delete_obj(obj_id=healthmonitor_id,
                                ignore_errors=ignore_errors)
