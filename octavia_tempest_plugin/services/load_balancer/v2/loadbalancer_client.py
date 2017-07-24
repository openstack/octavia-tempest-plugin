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

import json

from tempest import config
from tempest.lib.common import rest_client

CONF = config.CONF


class LoadbalancerClient(rest_client.RestClient):

    _uri = '/v2.0/lbaas/loadbalancers'

    def __init__(self, auth_provider, service, region, **kwargs):
        super(LoadbalancerClient, self).__init__(auth_provider, service,
                                                 region, **kwargs)
        self.timeout = CONF.load_balancer.lb_build_timeout
        self.build_interval = CONF.load_balancer.lb_build_interval
        self.resource_name = 'load balancer'
        self.get_status = self.show_loadbalancer

    def list_loadbalancers(self, query_params=None, return_object_only=True):
        """Get a list of load balancers.

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
        :returns: A list of load balancers object.
        """
        if query_params:
            request_uri = '{0}?{1}'.format(self._uri, query_params)
        else:
            request_uri = self._uri
        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return json.loads(body.decode('utf-8'))['loadbalancers']
        else:
            return json.loads(body.decode('utf-8'))

    def create_loadbalancer_dict(self, lb_dict, return_object_only=True):
        """Create a load balancer using a dictionary.

        Example lb_dict::

          lb_dict = {'loadbalancer': {
              'vip_network_id': 'd0be73da-921a-4e03-9c49-f13f18f7e39f',
              'name': 'TEMPEST_TEST_LB',
              'description': 'LB for Tempest tests'}
          }

        :param lb_dict: A dictionary describing the load balancer.
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
        :returns: A load balancer object.
        """
        response, body = self.post(self._uri, json.dumps(lb_dict))
        self.expected_success(201, response.status)
        if return_object_only:
            return json.loads(body.decode('utf-8'))['loadbalancer']
        else:
            return json.loads(body.decode('utf-8'))

    def create_loadbalancer(self, admin_state_up=None, description=None,
                            flavor=None, listeners=None, name=None,
                            project_id=None, provider=None, vip_address=None,
                            vip_network_id=None, vip_port_id=None,
                            vip_qos_policy_id=None, vip_subnet_id=None,
                            return_object_only=True):
        """Create a load balancer.

        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param description: A human-readable description for the resource.
        :param flavor: The load balancer flavor ID.
        :param listeners: A list of listner dictionaries.
        :param name: Human-readable name of the resource.
        :param project_id: The ID of the project owning this resource.
        :param provider: Provider name for the load balancer.
        :param vip_address: The IP address of the Virtual IP (VIP).
        :param vip_network_id: The ID of the network for the Virtual IP (VIP).
        :param vip_port_id: The ID of the Virtual IP (VIP) port.
        :param vip_qos_policy_id: The ID of the QoS Policy which will apply to
                                  the Virtual IP (VIP).
        :param vip_subnet_id: The ID of the subnet for the Virtual IP (VIP).
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
        :returns: A load balancer object.
        """
        method_args = locals()
        lb_params = {}
        for param, value in method_args.items():
            if param not in ('self',
                             'return_object_only') and value is not None:
                lb_params[param] = value
        lb_dict = {'loadbalancer': lb_params}
        return self.create_loadbalancer_dict(lb_dict, return_object_only)

    def delete_loadbalancer(self, lb_id, cascade=False, ignore_errors=False):
        """Delete a load balancer.

        :param lb_id: The load balancer ID to delete.
        :param cascade: If true will delete all child objects of the
                        load balancer.
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
        if cascade:
            uri = '{0}/{1}?cascade=true'.format(self._uri, lb_id)
        else:
            uri = '{0}/{1}'.format(self._uri, lb_id)
        if ignore_errors:
            try:
                response, body = self.delete(uri)
            except ignore_errors:
                return
        else:
            response, body = self.delete(uri)

        self.expected_success(204, response.status)
        return response.status

    def failover_loadbalancer(self, lb_id):
        """Failover a load balancer.

        :param lb_id: The load balancer ID to query.
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
        uri = '{0}/{1}/failover'.format(self._uri, lb_id)
        response, body = self.put(uri, '')
        self.expected_success(202, response.status)
        return

    def show_loadbalancer(self, lb_id, query_params=None,
                          return_object_only=True):
        """Get load balancer details.

        :param lb_id: The load balancer ID to query.
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
        :returns: A load balancer object.
        """
        if query_params:
            request_uri = '{0}/{1}?{2}'.format(self._uri, lb_id, query_params)
        else:
            request_uri = '{0}/{1}'.format(self._uri, lb_id)

        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return json.loads(body.decode('utf-8'))['loadbalancer']
        else:
            return json.loads(body.decode('utf-8'))

    def get_loadbalancer_stats(self, lb_id, query_params=None,
                               return_object_only=True):
        """Get load balancer statistics.

        :param lb_id: The load balancer ID to query.
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
        :returns: A load balancer statistics object.
        """
        if query_params:
            request_uri = '{0}/{1}/stats?{2}'.format(self._uri, lb_id,
                                                     query_params)
        else:
            request_uri = '{0}/{1}/stats'.format(self._uri, lb_id)

        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return json.loads(body.decode('utf-8'))['stats']
        else:
            return json.loads(body.decode('utf-8'))

    def get_loadbalancer_status(self, lb_id, query_params=None,
                                return_object_only=True):
        """Get a load balancer status tree.

        :param lb_id: The load balancer ID to query.
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
        :returns: A load balancer statuses object.
        """
        if query_params:
            request_uri = '{0}/{1}/status?{2}'.format(self._uri, lb_id,
                                                      query_params)
        else:
            request_uri = '{0}/{1}/status'.format(self._uri, lb_id)

        response, body = self.get(request_uri)
        self.expected_success(200, response.status)
        if return_object_only:
            return json.loads(body.decode('utf-8'))['statuses']
        else:
            return json.loads(body.decode('utf-8'))

    def update_loadbalancer_dict(self, lb_id, lb_dict,
                                 return_object_only=True):
        """Update a load balancer using a dictionary.

        Example lb_dict::

          lb_dict = {'loadbalancer': {'name': 'TEMPEST_TEST_LB_UPDATED'} }

        :param lb_id: The load balancer ID to update.
        :param lb_dict: A dictionary of elements to update on the load
                        balancer.
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
        :returns: A load balancer object.
        """
        uri = '{0}/{1}'.format(self._uri, lb_id)
        response, body = self.put(uri, json.dumps(lb_dict))
        self.expected_success(200, response.status)
        if return_object_only:
            return json.loads(body.decode('utf-8'))['loadbalancer']
        else:
            return json.loads(body.decode('utf-8'))

    def update_loadbalancer(self, lb_id, admin_state_up=None, description=None,
                            name=None, vip_qos_policy_id=None,
                            return_object_only=True):
        """Update a load balancer.

        :param lb_id: The load balancer ID to update.
        :param admin_state_up: The administrative state of the resource, which
                               is up (true) or down (false).
        :param description: A human-readable description for the resource.
        :param name: Human-readable name of the resource.
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
        :returns: A load balancer object.
        """
        method_args = locals()
        lb_params = {}
        for param, value in method_args.items():
            if param not in ('self', 'lb_id',
                             'return_object_only') and value is not None:
                lb_params[param] = value
        lb_dict = {'loadbalancer': lb_params}
        return self.update_loadbalancer_dict(lb_id, lb_dict,
                                             return_object_only)
