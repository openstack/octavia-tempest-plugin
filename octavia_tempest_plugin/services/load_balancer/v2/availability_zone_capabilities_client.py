#   Copyright 2019 Rackspace US Inc.  All rights reserved.
#   Copyright 2019 Verizon Media
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

from octavia_tempest_plugin.common.decorators import skip_if_not_implemented
from octavia_tempest_plugin.services.load_balancer.v2 import base_client
from octavia_tempest_plugin.services.load_balancer.v2 import provider_client

Unset = base_client.Unset


class AvailabilityZoneCapabilitiesClient(base_client.BaseLBaaSClient):

    list_root_tag = 'availability_zone_capabilities'

    def __init__(self, *args, **kwargs):
        super(AvailabilityZoneCapabilitiesClient, self).__init__(
            *args, **kwargs)
        providers_list_root_tag = provider_client.ProviderClient.list_root_tag
        # /v2.0/lbaas/providers/<PROVIDER_UUID>/availability_zone_capabilities
        self.uri = "{provider_base_uri}/{parent}/{object}".format(
            provider_base_uri=self.base_uri.format(
                object=providers_list_root_tag),
            parent="{parent}",
            object=self.list_root_tag
        )

    @skip_if_not_implemented
    def list_availability_zone_capabilities(self, provider, query_params=None,
                                            return_object_only=True):
        """Get a list of provider availability zone capability objects.

        :param provider: The provider to query for availability zone
                         capabilities.
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
        :returns: A list of availability zone capability objects.
        """
        return self._list_objects(parent_id=provider,
                                  query_params=query_params,
                                  return_object_only=return_object_only)
