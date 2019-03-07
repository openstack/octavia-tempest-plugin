# Copyright 2016 Rackspace Inc.
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
from oslo_log import log as logging

from octavia_tempest_plugin.common import constants as const


LOG = logging.getLogger(__name__)

service_available_group = cfg.OptGroup(name='service_available',
                                       title='Available OpenStack Services')

ServiceAvailableGroup = [
    cfg.BoolOpt('load_balancer',
                default=True,
                help="Whether or not the load-balancer service is expected "
                     "to be available."),
]

octavia_group = cfg.OptGroup(name='load_balancer',
                             title='load-balancer service options')

OctaviaGroup = [
    # Tempest plugin common options
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
               help="The endpoint type to use for the load-balancer service"),
    cfg.IntOpt('build_interval',
               default=5,
               help='Time in seconds between build status checks for '
                    'non-load-balancer resources to build'),
    cfg.IntOpt('build_timeout',
               default=300,
               help='Timeout in seconds to wait for non-load-balancer '
                    'resources to build'),
    cfg.StrOpt('octavia_svc_username', default='admin',
               help='The service_auth username the Octavia services are using'
                    'to access other OpenStack services.'),
    # load-balancer specific options
    cfg.IntOpt('check_interval',
               default=5,
               help='Interval to check for status changes.'),
    cfg.IntOpt('check_timeout',
               default=60,
               help='Timeout, in seconds, to wait for a status change.'),
    cfg.BoolOpt('test_with_noop',
                default=False,
                help='Runs the tests assuming no-op drivers are being used. '
                     'Tests will assume no actual amphora are created.'),
    cfg.IntOpt('lb_build_interval',
               default=10,
               help='Time in seconds between build status checks for a '
                    'load balancer.'),
    cfg.IntOpt('lb_build_timeout',
               default=900,
               help='Timeout in seconds to wait for a '
                    'load balancer to build.'),
    cfg.StrOpt('member_role',
               default='load-balancer_member',
               help='The load balancing member RBAC role.'),
    cfg.StrOpt('admin_role',
               default='load-balancer_admin',
               help='The load balancing admin RBAC role.'),
    cfg.IntOpt('scp_connection_timeout',
               default=5,
               help='Timeout in seconds to wait for a '
                    'scp connection to complete.'),
    cfg.IntOpt('scp_connection_attempts',
               default=20,
               help='Retries for scp to attempt to connect.'),
    cfg.StrOpt('provider',
               default='octavia',
               help='The provider driver to use for the tests.'),
    cfg.StrOpt('RBAC_test_type', default=const.ADVANCED,
               choices=[const.ADVANCED, const.OWNERADMIN, const.NONE],
               help='Type of RBAC tests to run. "advanced" runs the octavia '
                    'default RBAC tests. "owner_or_admin" runs the legacy '
                    'owner or admin tests. "none" disables the RBAC tests.'),
    cfg.DictOpt('enabled_provider_drivers',
                help=('List of enabled provider drivers and description '
                      'dictionaries. Must match the driver name in the '
                      'octavia.api.drivers entrypoint. Example: '
                      '{\'amphora\': \'The Octavia Amphora driver.\', '
                      '\'octavia\': \'Deprecated alias of the Octavia '
                      'Amphora driver.\'}'),
                default={'amphora': 'The Octavia Amphora driver.',
                         'octavia': 'Deprecated alias of the Octavia Amphora '
                         'driver.'}),
    # Networking
    cfg.BoolOpt('test_with_ipv6',
                default=True,
                help='When true the IPv6 tests will be run.'),
    cfg.BoolOpt('disable_boot_network', default=False,
                help='True if your cloud does not allow creating networks or '
                     'specifying the boot network for instances.'),
    cfg.BoolOpt('enable_security_groups', default=False,
                help='When true, security groups will be created for the test '
                     'servers. When false, port security will be disabled on '
                     'the created networks.'),
    cfg.StrOpt('test_network_override',
               help='Overrides network creation and uses this network ID for '
                    'all tests (VIP, members, etc.). Required if '
                    'test_subnet_override is set.'),
    cfg.StrOpt('test_subnet_override',
               help='Overrides subnet creation and uses this subnet ID for '
                    'all IPv4 tests (VIP, members, etc.). Optional'),
    cfg.StrOpt('test_ipv6_subnet_override',
               help='Overrides subnet creation and uses this subnet ID for '
                    'all IPv6 tests (VIP, members, etc.). Optional and only '
                    'valid if test_network_override is set.'),
    cfg.StrOpt('vip_subnet_cidr',
               default='10.1.1.0/24',
               help='CIDR format subnet to use for the vip subnet.'),
    cfg.StrOpt('vip_ipv6_subnet_cidr',
               default='fdde:1a92:7523:70a0::/64',
               help='CIDR format subnet to use for the IPv6 vip subnet.'),
    cfg.StrOpt('member_1_ipv4_subnet_cidr',
               default='10.2.1.0/24',
               help='CIDR format subnet to use for the member 1 subnet.'),
    cfg.StrOpt('member_1_ipv6_subnet_cidr',
               default='fd7b:f9f7:0fff:4eca::/64',
               help='CIDR format subnet to use for the member 1 ipv6 subnet.'),
    cfg.StrOpt('member_2_ipv4_subnet_cidr',
               default='10.2.2.0/24',
               help='CIDR format subnet to use for the member 2 subnet.'),
    cfg.StrOpt('member_2_ipv6_subnet_cidr',
               default='fd77:1457:4cf0:26a8::/64',
               help='CIDR format subnet to use for the member 1 ipv6 subnet.'),
    # Environment specific options
    # These are used to accomidate clouds with specific limitations
    cfg.IntOpt('random_server_name_length',
               default=0,
               help='If non-zero, generate a random name of the length '
                    'provided for each server, in the format "m[A-Z0-9]*". '),
    cfg.StrOpt('availability_zone',
               default=None,
               help='Availability zone to use for creating servers.'),
]

lb_feature_enabled_group = cfg.OptGroup(name='loadbalancer-feature-enabled',
                                        title='Enabled/Disabled LB features')
LBFeatureEnabledGroup = [
    cfg.BoolOpt('health_monitor_enabled',
                default=True,
                help="Whether Health Monitor is available with provider"
                     " driver or not."),
    cfg.BoolOpt('terminated_tls_enabled',
                default=True,
                help="Whether TLS termination is available with provider "
                     "driver or not."),
    cfg.BoolOpt('l7_protocol_enabled',
                default=True,
                help="Whether L7 Protocols are available with the provider"
                     " driver or not."),
    cfg.StrOpt('l4_protocol',
               default="TCP",
               help="The type of L4 Protocol which is supported with the"
                    " provider driver."),
]
