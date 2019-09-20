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
    flavor_capabilities_client)
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


class ManagerV2(clients.Manager):

    def __init__(self, credentials):
        super(ManagerV2, self).__init__(credentials)

        params = dict(self.default_params)
        params.update({
            'auth_provider': self.auth_provider,
            'service': CONF.load_balancer.catalog_type,
            'region': CONF.load_balancer.region or CONF.identity.region,
            'endpoint_type': CONF.load_balancer.endpoint_type,
            'build_interval': CONF.load_balancer.build_interval,
            'build_timeout': CONF.load_balancer.build_timeout
        })

        self.loadbalancer_client = loadbalancer_client.LoadbalancerClient(
            **params)
        self.listener_client = listener_client.ListenerClient(**params)
        self.pool_client = pool_client.PoolClient(**params)
        self.member_client = member_client.MemberClient(**params)
        self.healthmonitor_client = healthmonitor_client.HealthMonitorClient(
            **params)
        self.l7policy_client = l7policy_client.L7PolicyClient(**params)
        self.l7rule_client = l7rule_client.L7RuleClient(**params)
        self.amphora_client = amphora_client.AmphoraClient(**params)
        self.flavor_profile_client = flavor_profile_client.FlavorProfileClient(
            **params)
        self.flavor_client = flavor_client.FlavorClient(**params)
        self.provider_client = provider_client.ProviderClient(**params)
        self.flavor_capabilities_client = (
            flavor_capabilities_client.FlavorCapabilitiesClient(**params))
