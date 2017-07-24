# Copyright 2017 GoDaddy
# Copyright 2017 Catalyst IT Ltd
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
from tempest.lib import exceptions

from octavia_tempest_plugin.services.v2 import base as client_base


class LoadbalancerClient(client_base.LoadbalancerClientBase):
    """Tempest REST client for Octavia V2 API."""

    def delete_resource(self, res, id, ignore_error=False, cascade=False):
        try:
            resp, _ = self.delete_obj(res, id, cascade=cascade)
            return resp
        except (exceptions.NotFound, exceptions.Conflict):
            if ignore_error:
                return None
