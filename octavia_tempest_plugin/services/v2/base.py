# Copyright 2017 Catalyst IT Ltd
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import json

from oslo_serialization import jsonutils
from tempest.lib.common import rest_client


class LoadbalancerClientBase(rest_client.RestClient):
    def get_list_objs(self, obj):
        resp, body = self.get('/v2.0/lbaas/%s' % obj)

        return resp, jsonutils.loads(body)

    def delete_obj(self, obj, id, cascade=False):
        url = '/v2.0/lbaas/{obj}/{id}'.format(obj=obj, id=id)
        if cascade:
            url += '?cascade=True'
        return self.delete(url)

    def get_obj(self, obj, id):
        resp, body = self.get('/v2.0/lbaas/{obj}/{id}'.format(obj=obj, id=id))

        return resp, jsonutils.loads(body)

    def post_json(self, obj, req_body, extra_headers={}):
        headers = {"Content-Type": "application/json"}
        headers = dict(headers, **extra_headers)
        url_path = '/v2.0/lbaas/%s' % obj

        resp, body = self.post(url_path, json.dumps(req_body), headers=headers)

        return resp, jsonutils.loads(body)

    def put_json(self, obj, id, req_body, extra_headers={}):
        headers = {"Content-Type": "application/json"}
        headers = dict(headers, **extra_headers)
        url_path = '/v2.0/lbaas/%s/%s' % (obj, id)

        resp, body = self.put(url_path, json.dumps(req_body), headers=headers)

        return resp, jsonutils.loads(body)
