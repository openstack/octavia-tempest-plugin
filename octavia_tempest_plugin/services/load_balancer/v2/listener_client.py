#   Copyright 2017 GoDaddy
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

from oslo_serialization import jsonutils

from tempest import config

from octavia_tempest_plugin.common.decorators import skip_if_not_implemented
from octavia_tempest_plugin.services.load_balancer.v2 import base_client

CONF = config.CONF
Unset = base_client.Unset


class ListenerClient(base_client.BaseLBaaSClient):

    root_tag = 'listener'
    list_root_tag = 'listeners'

    @skip_if_not_implemented
    def create_listener(self, protocol, protocol_port, loadbalancer_id,
                        name=Unset, description=Unset, tags=Unset,
                        admin_state_up=Unset, connection_limit=Unset,
                        timeout_client_data=Unset,
                        timeout_member_connect=Unset,
                        timeout_member_data=Unset, timeout_tcp_inspect=Unset,
                        insert_headers=Unset, default_pool_id=Unset,
                        default_tls_container_ref=Unset,
                        sni_container_refs=Unset, client_authentication=Unset,
                        client_ca_tls_container_ref=Unset,
                        client_crl_container_ref=Unset, allowed_cidrs=Unset,
                        alpn_protocols=Unset,
                        return_object_only=True):
        """Create a listener.

        :param protocol: The protocol for the resource.
        :param protocol_port: The protocol port number for the resource.
        :param loadbalancer_id: The ID of the load balancer.
        :param name: Human-readable name of the resource.
        :param description: A human-readable description for the resource.
        :param tags: A human-readable tags of the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param connection_limit: The maximum number of connections permitted
                                 for this listener. Default value is -1 which
                                 represents infinite connections.
        :param timeout_client_data: Frontend client inactivity timeout in
                                    milliseconds.
        :param timeout_member_connect: Backend member connection timeout in
                                       milliseconds.
        :param timeout_member_data: Backend member inactivity timeout in
                                    milliseconds.
        :param timeout_tcp_inspect: Time, in milliseconds, to wait for
                                    additional TCP packets for content
                                    inspection.
        :param insert_headers: A dictionary of optional headers to insert into
                               the request before it is sent to the backend
                               member.
        :param default_pool_id: The ID of the pool used by the listener if no
                                L7 policies match.
        :param default_tls_container_ref: The URI of the key manager service
                                          secret containing a PKCS12 format
                                          certificate/key bundle for
                                          TERMINATED_TLS listeners.
        :param sni_container_refs: A list of URIs to the key manager service
                                   secrets containing PKCS12 format
                                   certificate/key bundles for TERMINATED_TLS
                                   listeners.
        :param client_authentication: The TLS client authentication mode. One
                                      of the options NONE, OPTIONAL or
                                      MANDATORY.
        :param client_ca_tls_container_ref: The ref of the key manager service
                                            secret containing a PEM format
                                            client CA certificate bundle for
                                            TERMINATED_HTTPS listeners.
        :param client_crl_container_ref: The URI of the key manager service
                                         secret containing a PEM format CA
                                         revocation list file for
                                         TERMINATED_HTTPS listeners.
        :param allowed_cidrs: A list of IPv4 or IPv6 CIDRs.
        :param alpn_protocols: A list of ALPN protocols for TERMINATED_HTTPS
                               listeners.
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
        :returns: A listener object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        return self._create_object(**kwargs)

    @skip_if_not_implemented
    def show_listener(self, listener_id, query_params=None,
                      return_object_only=True):
        """Get listener details.

        :param listener_id: The listener ID to query.
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
        :returns: A listener object.
        """
        return self._show_object(obj_id=listener_id,
                                 query_params=query_params,
                                 return_object_only=return_object_only)

    @skip_if_not_implemented
    def list_listeners(self, query_params=None, return_object_only=True):
        """Get a list of listener objects.

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
        :returns: A list of listener objects.
        """
        return self._list_objects(query_params=query_params,
                                  return_object_only=return_object_only)

    @skip_if_not_implemented
    def update_listener(self, listener_id, name=Unset, description=Unset,
                        tags=Unset, admin_state_up=Unset,
                        connection_limit=Unset, timeout_client_data=Unset,
                        timeout_member_connect=Unset,
                        timeout_member_data=Unset, timeout_tcp_inspect=Unset,
                        insert_headers=Unset, default_pool_id=Unset,
                        default_tls_container_ref=Unset,
                        sni_container_refs=Unset, client_authentication=Unset,
                        client_ca_tls_container_ref=Unset,
                        client_crl_container_ref=Unset, allowed_cidrs=Unset,
                        alpn_protocols=Unset,
                        return_object_only=True):
        """Update a listener.

        :param listener_id: The listener ID to update.
        :param name: Human-readable name of the resource.
        :param description: A human-readable description for the resource.
        :param tags: A human-readable tags of the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param connection_limit: The maximum number of connections permitted
                                 for this listener. Default value is -1 which
                                 represents infinite connections.
        :param timeout_client_data: Frontend client inactivity timeout in
                                    milliseconds.
        :param timeout_member_connect: Backend member connection timeout in
                                       milliseconds.
        :param timeout_member_data: Backend member inactivity timeout in
                                    milliseconds.
        :param timeout_tcp_inspect: Time, in milliseconds, to wait for
                                    additional TCP packets for content
                                    inspection.
        :param insert_headers: A dictionary of optional headers to insert into
                               the request before it is sent to the backend
                               member.
        :param default_pool_id: The ID of the pool used by the listener if no
                                L7 policies match.
        :param default_tls_container_ref: The URI of the key manager service
                                          secret containing a PKCS12 format
                                          certificate/key bundle for
                                          TERMINATED_TLS listeners.
        :param sni_container_refs: A list of URIs to the key manager service
                                   secrets containing PKCS12 format
                                   certificate/key bundles for TERMINATED_TLS
                                   listeners.
        :param client_authentication: The TLS client authentication mode. One
                                      of the options NONE, OPTIONAL or
                                      MANDATORY.
        :param client_ca_tls_container_ref: The ref of the key manager service
                                            secret containing a PEM format
                                            client CA certificate bundle for
                                            TERMINATED_HTTPS listeners.
        :param client_crl_container_ref: The URI of the key manager service
                                         secret containing a PEM format CA
                                         revocation list file for
                                         TERMINATED_HTTPS listeners.
        :param allowed_cidrs: A list of IPv4 or IPv6 CIDRs.
        :param alpn_protocols: A list of ALPN protocols for TERMINATED_HTTPS
                               listeners.
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
        :returns: A listener object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('listener_id')
        return self._update_object(**kwargs)

    @skip_if_not_implemented
    def delete_listener(self, listener_id, ignore_errors=False):
        """Delete a listener.

        :param listener_id: The listener ID to delete.
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
        return self._delete_obj(obj_id=listener_id,
                                ignore_errors=ignore_errors)

    @skip_if_not_implemented
    def get_listener_stats(self, listener_id, query_params=None,
                           return_object_only=True):
        """Get listener statistics.

        :param listener_id: The listener ID to query.
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
        :returns: A listener statistics object.
        """
        if query_params:
            request_uri = '{0}/{1}/stats?{2}'.format(self.uri, listener_id,
                                                     query_params)
        else:
            request_uri = '{0}/{1}/stats'.format(self.uri, listener_id)

        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return jsonutils.loads(body.decode('utf-8'))['stats']
        else:
            return jsonutils.loads(body.decode('utf-8'))
