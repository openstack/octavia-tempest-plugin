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

from oslo_log import log as logging
from oslo_serialization import jsonutils
from tempest import config

from octavia_tempest_plugin.common.decorators import skip_if_not_implemented
from octavia_tempest_plugin.services.load_balancer.v2 import base_client
from octavia_tempest_plugin.services.load_balancer.v2 import pool_client

CONF = config.CONF
LOG = logging.getLogger(__name__)
Unset = base_client.Unset


class MemberClient(base_client.BaseLBaaSClient):

    root_tag = 'member'
    list_root_tag = 'members'

    def __init__(self, *args, **kwargs):
        super(MemberClient, self).__init__(*args, **kwargs)
        pool_list_root_tag = pool_client.PoolClient.list_root_tag
        # /v2.0/lbaas/pools/<POOL_UUID>/members
        self.uri = "{pool_base_uri}/{parent}/{object}".format(
            pool_base_uri=self.base_uri.format(object=pool_list_root_tag),
            parent="{parent}",
            object=self.list_root_tag
        )

    @skip_if_not_implemented
    def create_member(self, pool_id, address, protocol_port,
                      name=Unset, tags=Unset, admin_state_up=Unset,
                      weight=Unset,
                      backup=Unset, subnet_id=Unset, monitor_address=Unset,
                      monitor_port=Unset, return_object_only=True):
        """Create a member.

        :param pool_id: The ID of the pool where the member will live.
        :param address: The IP address of the resource.
        :param protocol_port: The protocol port number for the resource.
        :param name: Human-readable name of the resource.
        :param tags: Human-readable tags of the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param weight: The weight of a member determines the portion of
                       requests or connections it services compared to the
                       other members of the pool.
        :param backup: Is the member a backup?
        :param subnet_id: The subnet ID which the member service
                                 is accessible from
        :param monitor_address: An alternate IP address used for health
                                monitoring a backend member.
        :param monitor_port: An alternate protocol port used for health
                             monitoring a backend member.
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
        :returns: A member object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['parent_id'] = kwargs.pop('pool_id')
        return self._create_object(**kwargs)

    @skip_if_not_implemented
    def show_member(self, member_id, pool_id, query_params=None,
                    return_object_only=True):
        """Get member details.

        :param member_id: The member ID to query.
        :param pool_id: The ID of the pool where the member lives.
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
        :returns: A member object.
        """
        return self._show_object(obj_id=member_id,
                                 parent_id=pool_id,
                                 query_params=query_params,
                                 return_object_only=return_object_only)

    @skip_if_not_implemented
    def list_members(self, pool_id, query_params=None,
                     return_object_only=True):
        """Get a list of member objects.

        :param pool_id: The ID of the pool where the members live.
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
        :returns: A list of member objects.
        """
        return self._list_objects(parent_id=pool_id,
                                  query_params=query_params,
                                  return_object_only=return_object_only)

    @skip_if_not_implemented
    def update_member(self, member_id, pool_id, name=Unset, tags=Unset,
                      admin_state_up=Unset, weight=Unset, backup=Unset,
                      monitor_address=Unset, monitor_port=Unset,
                      return_object_only=True):
        """Update a member.

        :param member_id: The member ID to update.
        :param pool_id: The ID of the pool where the member lives.
        :param name: Human-readable name of the resource.
        :param tags: Human-readable tags of the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param weight: The weight of a member determines the portion of
                       requests or connections it services compared to the
                       other members of the pool.
        :param backup: Is the member a backup?
        :param monitor_address: An alternate IP address used for health
                                monitoring a backend member.
        :param monitor_port: An alternate protocol port used for health
                             monitoring a backend member.
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
        :returns: A member object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('member_id')
        kwargs['parent_id'] = kwargs.pop('pool_id')
        return self._update_object(**kwargs)

    @skip_if_not_implemented
    def update_members(self, pool_id, members_list):
        """Batch update all members on a pool.

        :param pool_id: The ID of the pool where the members live.
        :param members_list: The list of members to enforce on the pool.
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
        :returns: A member object.
        """
        obj_dict = {self.list_root_tag: members_list}
        request_uri = self.uri.format(parent=pool_id)

        response, body = self.put(request_uri, jsonutils.dumps(obj_dict))
        self.expected_success(202, response.status)
        return

    @skip_if_not_implemented
    def delete_member(self, member_id, pool_id, ignore_errors=False):
        """Delete a member.

        :param member_id: The member ID to delete.
        :param pool_id: The ID of the pool where the member lives.
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
        return self._delete_obj(obj_id=member_id,
                                parent_id=pool_id,
                                ignore_errors=ignore_errors)

    def cleanup_member(self, member_id, pool_id, lb_client=None, lb_id=None):
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('member_id')
        kwargs['parent_id'] = kwargs.pop('pool_id')
        return self._cleanup_obj(**kwargs)

    def is_resource_deleted(self, id):
        # Trying to implement this for members would be impossible, because
        # they are sub-objects that can't be referenced directly, and this is
        # used internally in tempest where we have no control over passed args
        raise NotImplementedError()
