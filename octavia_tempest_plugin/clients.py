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
from tempest import clients
from tempest import config

from octavia_tempest_plugin.services.load_balancer.v2 import (
    amphora_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    flavor_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    flavor_profile_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    healthmonitor_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    l7policy_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    l7rule_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    listener_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    loadbalancer_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    member_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    pool_client)
from octavia_tempest_plugin.services.load_balancer.v2 import (
    provider_client)

CONF = config.CONF
SERVICE_TYPE = 'load-balancer'


class ManagerV2(clients.Manager):

    def __init__(self, credentials):
        super(ManagerV2, self).__init__(credentials)

        self.loadbalancer_client = loadbalancer_client.LoadbalancerClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.listener_client = listener_client.ListenerClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.pool_client = pool_client.PoolClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.member_client = member_client.MemberClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.healthmonitor_client = healthmonitor_client.HealthMonitorClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.l7policy_client = l7policy_client.L7PolicyClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.l7rule_client = l7rule_client.L7RuleClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.amphora_client = amphora_client.AmphoraClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.flavor_profile_client = flavor_profile_client.FlavorProfileClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.flavor_client = flavor_client.FlavorClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
        self.provider_client = provider_client.ProviderClient(
            self.auth_provider, SERVICE_TYPE, CONF.identity.region)
