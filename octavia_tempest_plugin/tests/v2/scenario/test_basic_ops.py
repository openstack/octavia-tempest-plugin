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
from oslo_log import log as logging

from tempest import config
from tempest.lib.common import validation_resources as vr
from tempest.lib import decorators

from octavia_tempest_plugin.tests.v2 import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class BasicOpsTest(base.BaseLoadbalancerTest):
    name_prefix = 'Tempest-BasicOpsTest'

    def setUp(self):
        super(BasicOpsTest, self).setUp()

        # Setup network resources for instance
        resources = dict(
            keypair=True,
            security_group=True,
            security_group_rules=True,
            floating_ip=CONF.validation.connect_method == 'floating'
        )
        self.vr = self.useFixture(
            vr.ValidationResourcesFixture(
                self.os_roles_lbmember,
                use_neutron=True,
                floating_network_id=CONF.network.public_network_id,
                **resources
            )
        )

        # Add security group rule to allow http request
        self.sg_rule_client.create_security_group_rule(
            security_group_id=self.vr.resources['security_group']['id'],
            protocol='tcp',
            ethertype='IPv4',
            port_range_min=80,
            port_range_max=81,
            direction='ingress'
        )

        self.create_backend()

    @decorators.idempotent_id('250ebc41-645e-43fb-a79a-e3035f338e2a')
    @decorators.attr(type='slow')
    def test_basic_ops(self):
        # Create loadbalancer
        params = {}
        if self.vip_network_id:
            params['vip_network_id'] = self.vip_network_id
        if self.vip_subnet_id:
            params['vip_subnet_id'] = self.vip_subnet_id

        self.create_loadbalancer(**params)

        # Create pool
        pool = self.create_pool(self.lb_id)
        self.pool_id = pool['id']

        # Create listener
        params = {'default_pool_id': self.pool_id}
        listener = self.create_listener(self.lb_id, **params)
        self.listener_id = listener['id']

        # Add members to the pool
        for port in [80, 81]:
            params = {
                'address': self.vm_ip,
                'protocol_port': port,
            }
            if self.member_subnet_id:
                params['subnet_id'] = self.member_subnet_id

            self.create_member(self.pool_id, self.lb_id, **params)

        self.check_members_balanced()
