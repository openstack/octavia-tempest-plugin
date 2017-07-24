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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from octavia_tempest_plugin.tests.v2 import base


class LoadbalancerTest(base.BaseLoadbalancerTest):
    name_prefix = 'Tempest-LoadbalancerTest'

    @decorators.idempotent_id('94c66b04-1ab3-4375-a921-89e48d833c1d')
    @decorators.attr(type='slow')
    def test_crud_loadbalancer(self):
        # Create loadbalancer
        params = {}
        if self.vip_network_id:
            params['vip_network_id'] = self.vip_network_id
        if self.vip_subnet_id:
            params['vip_subnet_id'] = self.vip_subnet_id
        lb_id = self.create_loadbalancer(**params)['id']

        # Get loadbalancers
        resp, body = self.lb_client.get_list_objs('loadbalancers')
        self.assertEqual(200, resp.status)
        self.assertIn(
            lb_id,
            [item['id'] for item in body['loadbalancers']]
        )

        # Update loadbalancer
        new_name = data_utils.rand_name('lb', prefix=self.name_prefix)
        self.update_loadbalancer(lb_id, name=new_name)

        # Get loadbalancer
        resp, body = self.lb_client.get_obj('loadbalancers', lb_id)
        self.assertEqual(200, resp.status)
        self.assertEqual(new_name, body['loadbalancer']['name'])

        # Delete loadbalancer
        self.delete_loadbalancer(lb_id)

        # Get loadbalancers
        resp, body = self.lb_client.get_list_objs('loadbalancers')
        self.assertEqual(200, resp.status)
        self.assertNotIn(
            lb_id,
            [item['id'] for item in body['loadbalancers']]
        )
