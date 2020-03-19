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


class LoadbalancerClient(base_client.BaseLBaaSClient):

    root_tag = 'loadbalancer'
    list_root_tag = 'loadbalancers'

    def __init__(self, auth_provider, service, region, **kwargs):
        super(LoadbalancerClient, self).__init__(auth_provider, service,
                                                 region, **kwargs)
        self.timeout = CONF.load_balancer.lb_build_timeout
        self.build_interval = CONF.load_balancer.lb_build_interval

    @skip_if_not_implemented
    def create_loadbalancer(self, name=Unset, description=Unset,
                            admin_state_up=Unset, flavor_id=Unset,
                            listeners=Unset, project_id=Unset, provider=Unset,
                            vip_address=Unset, vip_network_id=Unset,
                            vip_port_id=Unset, vip_qos_policy_id=Unset,
                            vip_subnet_id=Unset, return_object_only=True,
                            tags=Unset):
        """Create a loadbalancer.

        :param name: Human-readable name of the resource.
        :param description: A human-readable description for the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param flavor: The loadbalancer flavor ID.
        :param listeners: A list of listner dictionaries.
        :param project_id: The ID of the project owning this resource.
        :param provider: Provider name for the loadbalancer.
        :param vip_address: The IP address of the Virtual IP (VIP).
        :param vip_network_id: The ID of the network for the Virtual IP (VIP).
        :param vip_port_id: The ID of the Virtual IP (VIP) port.
        :param vip_qos_policy_id: The ID of the QoS Policy which will apply to
                                  the Virtual IP (VIP).
        :param vip_subnet_id: The ID of the subnet for the Virtual IP (VIP).
        :param tags: A human-readable tags of the resource.
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
        :returns: A loadbalancer object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        return self._create_object(**kwargs)

    @skip_if_not_implemented
    def show_loadbalancer(self, lb_id, query_params=None,
                          return_object_only=True):
        """Get loadbalancer details.

        :param lb_id: The loadbalancer ID to query.
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
        :returns: A loadbalancer object.
        """
        return self._show_object(obj_id=lb_id,
                                 query_params=query_params,
                                 return_object_only=return_object_only)

    @skip_if_not_implemented
    def list_loadbalancers(self, query_params=None, return_object_only=True):
        """Get a list of loadbalancer objects.

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
        :returns: A list of loadbalancer objects.
        """
        return self._list_objects(query_params=query_params,
                                  return_object_only=return_object_only)

    @skip_if_not_implemented
    def update_loadbalancer(self, lb_id, name=Unset, description=Unset,
                            tags=Unset, admin_state_up=Unset,
                            vip_qos_policy_id=Unset,
                            return_object_only=True):
        """Update a loadbalancer.

        :param lb_id: The loadbalancer ID to update.
        :param name: Human-readable name of the resource.
        :param description: A human-readable description for the resource.
        :param tags: A human-readable tags of the resource.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param vip_qos_policy_id: The ID of the QoS Policy which will apply to
                                  the Virtual IP (VIP).
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
        :returns: A loadbalancer object.
        """
        kwargs = {arg: value for arg, value in locals().items()
                  if arg != 'self' and value is not Unset}
        kwargs['obj_id'] = kwargs.pop('lb_id')
        return self._update_object(**kwargs)

    @skip_if_not_implemented
    def delete_loadbalancer(self, lb_id, cascade=False, ignore_errors=False):
        """Delete a loadbalancer.

        :param lb_id: The loadbalancer ID to delete.
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
        return self._delete_obj(obj_id=lb_id,
                                ignore_errors=ignore_errors,
                                cascade=cascade)

    @skip_if_not_implemented
    def failover_loadbalancer(self, lb_id):
        """Failover a loadbalancer.

        :param lb_id: The loadbalancer ID to query.
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
        :returns: None
        """
        uri = '{0}/{1}/failover'.format(self.uri, lb_id)
        response, body = self.put(uri, '')
        self.expected_success(202, response.status)
        return

    @skip_if_not_implemented
    def get_loadbalancer_stats(self, lb_id, query_params=None,
                               return_object_only=True):
        """Get loadbalancer statistics.

        :param lb_id: The loadbalancer ID to query.
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
        :returns: A loadbalancer statistics object.
        """
        if query_params:
            request_uri = '{0}/{1}/stats?{2}'.format(self.uri, lb_id,
                                                     query_params)
        else:
            request_uri = '{0}/{1}/stats'.format(self.uri, lb_id)

        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return jsonutils.loads(body.decode('utf-8'))['stats']
        else:
            return jsonutils.loads(body.decode('utf-8'))

    @skip_if_not_implemented
    def get_loadbalancer_status(self, lb_id, query_params=None,
                                return_object_only=True):
        """Get a loadbalancer status tree.

        :param lb_id: The loadbalancer ID to query.
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
        :returns: A loadbalancer statuses object.
        """
        if query_params:
            request_uri = '{0}/{1}/status?{2}'.format(self.uri, lb_id,
                                                      query_params)
        else:
            request_uri = '{0}/{1}/status'.format(self.uri, lb_id)

        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return jsonutils.loads(body.decode('utf-8'))['statuses']
        else:
            return jsonutils.loads(body.decode('utf-8'))
