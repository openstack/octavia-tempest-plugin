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
from octavia_tempest_plugin.services.load_balancer.v2 import l7policy_client

CONF = config.CONF
Unset = base_client.Unset


class L7RuleClient(base_client.BaseLBaaSClient):

    root_tag = 'rule'
    list_root_tag = 'rules'
    resource_name = 'l7rule'

    def __init__(self, *args, **kwargs):
        super(L7RuleClient, self).__init__(*args, **kwargs)
        l7policy_list_root_tag = l7policy_client.L7PolicyClient.list_root_tag
        # /v2.0/lbaas/l7policies/<L7POLICY_UUID>/rules
        self.uri = "{l7policy_base_uri}/{parent}/{object}".format(
            l7policy_base_uri=self.base_uri.format(
                object=l7policy_list_root_tag),
            parent="{parent}",
            object=self.list_root_tag
        )

    @skip_if_not_implemented
    def create_l7rule(self, l7policy_id, type, value, compare_type, tags=Unset,
                      admin_state_up=Unset, key=Unset, invert=Unset,
                      return_object_only=True):
        """Create a l7rule.

        :param l7policy_id: The ID of the l7policy for the l7rule.
        :param type: The L7 rule type.
        :param value: The value to use for the comparison.
        :param compare_type: The comparison type for the L7 rule.
        :param tags: The tags of the L7 rule.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param key: The key to use for the comparison.
        :param invert: When true the logic of the rule is inverted.
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
        :returns: A l7rule object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['parent_id'] = kwargs.pop('l7policy_id')
        return self._create_object(**kwargs)

    @skip_if_not_implemented
    def show_l7rule(self, l7rule_id, l7policy_id, query_params=None,
                    return_object_only=True):
        """Get l7rule details.

        :param l7rule_id: The l7rule ID to query.
        :param l7policy_id: The ID of the l7policy for the l7rule.
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
        :returns: A l7rule object.
        """
        return self._show_object(obj_id=l7rule_id,
                                 parent_id=l7policy_id,
                                 query_params=query_params,
                                 return_object_only=return_object_only)

    @skip_if_not_implemented
    def list_l7rules(self, l7policy_id, query_params=None,
                     return_object_only=True):
        """Get a list of l7rule objects.

        :param l7policy_id: The ID of the l7policy for the l7rule.
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
        :returns: A list of l7rule objects.
        """
        return self._list_objects(parent_id=l7policy_id,
                                  query_params=query_params,
                                  return_object_only=return_object_only)

    @skip_if_not_implemented
    def update_l7rule(self, l7rule_id, l7policy_id, type=Unset, value=Unset,
                      compare_type=Unset, tags=Unset, admin_state_up=Unset,
                      key=Unset, invert=Unset, return_object_only=True):
        """Update a l7rule.

        :param l7rule_id: The l7rule ID to update.
        :param l7policy_id: The ID of the l7policy for the l7rule.
        :param type: The L7 rule type.
        :param value: The value to use for the comparison.
        :param compare_type: The comparison type for the L7 rule.
        :param tags: The tags of the L7 rule.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param key: The key to use for the comparison.
        :param invert: When true the logic of the rule is inverted.
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
        :returns: A l7rule object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('l7rule_id')
        kwargs['parent_id'] = kwargs.pop('l7policy_id')
        return self._update_object(**kwargs)

    @skip_if_not_implemented
    def delete_l7rule(self, l7rule_id, l7policy_id, ignore_errors=False):
        """Delete a l7rule.

        :param l7rule_id: The l7rule ID to delete.
        :param l7policy_id: The ID of the l7policy for the l7rule.
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
        return self._delete_obj(obj_id=l7rule_id,
                                parent_id=l7policy_id,
                                ignore_errors=ignore_errors)

    def cleanup_l7rule(self, l7rule_id, l7policy_id, lb_client=None,
                       lb_id=None):
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('l7rule_id')
        kwargs['parent_id'] = kwargs.pop('l7policy_id')
        return self._cleanup_obj(**kwargs)

    def is_resource_deleted(self, id):
        # Trying to implement this for l7rules would be impossible, because
        # they are sub-objects that can't be referenced directly, and this is
        # used internally in tempest where we have no control over passed args
        raise NotImplementedError()
