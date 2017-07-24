# Copyright 2016 Rackspace Inc.
# Copyright 2017 Catalyst IT Ltd
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from oslo_config import cfg


service_option = cfg.BoolOpt(
    'loadbalancer',
    default=True,
    help="Whether or not loadbalancing service is expected to be available"
)

octavia_group = cfg.OptGroup(name='loadbalancer',
                             title='Loadbalancing Service Options')

OctaviaGroup = [
    cfg.StrOpt("region",
               default="",
               help="The region name to use. If empty, the value "
                    "of identity.region is used instead. If no such region "
                    "is found in the service catalog, the first found one is "
                    "used."),
    cfg.StrOpt('catalog_type',
               default='load-balancer',
               help='Catalog type of the Octavia service.'),
    cfg.StrOpt('endpoint_type',
               default='publicURL',
               choices=['public', 'admin', 'internal',
                        'publicURL', 'adminURL', 'internalURL'],
               help="The endpoint type to use for the Octavia service."),
    cfg.IntOpt('build_interval',
               default=5,
               help='Time in seconds between build status checks for '
                    'non-loadbalancer resources to build'),
    cfg.IntOpt('build_timeout',
               default=30,
               help='Timeout in seconds to wait for non-loadbalancer '
                    'resources to build'),
    cfg.IntOpt('lb_build_interval',
               default=10,
               help='Time in seconds between build status checks for a '
                    'loadbalancer.'),
    cfg.IntOpt('lb_build_timeout',
               default=900,
               help='Timeout in seconds to wait for a '
                    'loadbalancer to build.'),
    cfg.BoolOpt('premade_server',
                default=False,
                help='Allows us to use an already provisioned server to test '
                     'loadbalancing.'),
    cfg.StrOpt('premade_server_ip',
               default=None,
               help='IP of the premade server.'),
    cfg.StrOpt('premade_server_subnet_id',
               default=None,
               help='Subnet ID of the premade server.'),
    cfg.StrOpt('vip_network_id',
               default=None,
               help='Existing network ID to use for loadbalancer.'),
    cfg.StrOpt('vip_subnet_id',
               default=None,
               help='Existing subnet ID to use for loadbalancer.'),
    cfg.IntOpt('random_server_name_length',
               default=0,
               help='If non-zero, generate a random name of the length '
                    'provided for each server, in the format "m[A-Z0-9]*". '),
    cfg.StrOpt('availability_zone',
               default=None,
               help='Availability zone to use for creating servers.'),
    cfg.StrOpt('member_role',
               default='load-balancer_member',
               help="Role to add to users created for octavia tests."),
]
