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


class PoolClient(base_client.BaseLBaaSClient):

    root_tag = 'pool'
    list_root_tag = 'pools'
    resource_name = 'pool'

    @skip_if_not_implemented
    def create_pool(self, protocol, lb_algorithm, loadbalancer_id=Unset,
                    listener_id=Unset, name=Unset, description=Unset,
                    tags=Unset,
                    admin_state_up=Unset, session_persistence=Unset,
                    ca_tls_container_ref=Unset, crl_container_ref=Unset,
                    tls_enabled=Unset, tls_container_ref=Unset,
                    alpn_protocols=Unset, return_object_only=True):
        """Create a pool.

        :param protocol: The protocol for the resource.
        :param lb_algorithm: The load balancing algorithm for the pool.
        :param loadbalancer_id: The ID of the load balancer for the pool.
        :param listener_id: The ID of the listener for the pool.
        :param name: Human-readable name of the resource.
        :param description: A human-readable description for the resource.
        :param tags: A human-readable tags of the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param session_persistence: A JSON object specifying the session
                                    persistence for the pool or null for no
                                    session persistence.
        :param ca_tls_container_ref: The key manager ref for a secret
                                     containing the PEM encoded CA certificate
                                     to validate pool members against.
        :param crl_container_ref: The key manager ref for a secret containing
                                  the PEM encoded CRL to use when validating
                                  pool members.
        :param tls_enabled: A boolean, True when the pool should connect to
                            members using TLS.
        :param tls_container_ref: The key manager ref for a secret containing
                                  a PKCS12 bundle with the client
                                  authentication certificate and key used
                                  when connecting to pool members over TLS.
        :param alpn_protocols: A list of ALPN protocols for TLS enabled pools.
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
        :returns: A pool object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        return self._create_object(**kwargs)

    @skip_if_not_implemented
    def show_pool(self, pool_id, query_params=None, return_object_only=True):
        """Get pool details.

        :param pool_id: The pool ID to query.
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
        :returns: A pool object.
        """
        return self._show_object(obj_id=pool_id,
                                 query_params=query_params,
                                 return_object_only=return_object_only)

    @skip_if_not_implemented
    def list_pools(self, query_params=None, return_object_only=True):
        """Get a list of pool objects.

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
        :returns: A list of pool objects.
        """
        return self._list_objects(query_params=query_params,
                                  return_object_only=return_object_only)

    @skip_if_not_implemented
    def update_pool(self, pool_id, lb_algorithm=Unset, name=Unset,
                    description=Unset, tags=Unset, admin_state_up=Unset,
                    session_persistence=Unset, ca_tls_container_ref=Unset,
                    crl_container_ref=Unset, tls_enabled=Unset,
                    tls_container_ref=Unset, alpn_protocols=Unset,
                    return_object_only=True):
        """Update a pool.

        :param pool_id: The pool ID to update.
        :param lb_algorithm: The load balancing algorithm for the pool.
        :param name: Human-readable name of the resource.
        :param description: A human-readable description for the resource.
        :param tags: A human-readable tags of the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param session_persistence: A JSON object specifying the session
                                    persistence for the pool or null for no
                                    session persistence.
        :param ca_tls_container_ref: The key manager ref for a secret
                                     containing the PEM encoded CA certificate
                                     to validate pool members against.
        :param crl_container_ref: The key manager ref for a secret containing
                                  the PEM encoded CRL to use when validating
                                  pool members.
        :param tls_enabled: A boolean, True when the pool should connect to
                            members using TLS.
        :param tls_container_ref: The key manager ref for a secret containing
                                  a PKCS12 bundle with the client
                                  authentication certificate and key used
                                  when connecting to pool members over TLS.
        :param alpn_protocols: A list of ALPN protocols for TLS enabled pools.
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
        :returns: A pool object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('pool_id')
        return self._update_object(**kwargs)

    @skip_if_not_implemented
    def delete_pool(self, pool_id, ignore_errors=False):
        """Delete a pool.

        :param pool_id: The pool ID to delete.
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
        return self._delete_obj(obj_id=pool_id,
                                ignore_errors=ignore_errors)
