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
    cfg.FloatOpt('build_interval',
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
    cfg.FloatOpt('check_interval',
                 default=5,
                 help='Interval to check for status changes.'),
    cfg.IntOpt('check_timeout',
               default=120,
               help='Timeout, in seconds, to wait for a status change.'),
    cfg.BoolOpt('test_with_noop',
                default=False,
                help='Runs the tests assuming no-op drivers are being used. '
                     'Tests will assume no actual amphora are created.'),
    cfg.FloatOpt('lb_build_interval',
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
    cfg.StrOpt('observer_role',
               default='load-balancer_observer',
               help='The load balancing observer RBAC role.'),
    cfg.StrOpt('global_observer_role',
               default='load-balancer_global_observer',
               help='The load balancing global observer RBAC role.'),
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
               choices=[const.ADVANCED, const.KEYSTONE_DEFAULT_ROLES,
                        const.OWNERADMIN, const.NONE],
               help='Type of RBAC tests to run. "advanced" runs the octavia '
                    'default RBAC tests. "owner_or_admin" runs the legacy '
                    'owner or admin tests. "keystone_default_roles" runs the '
                    'tests using only the keystone default roles. "none" '
                    'disables the RBAC tests.'),
    cfg.DictOpt('enabled_provider_drivers',
                help=('A comma separated list of dictionaries of the '
                      'enabled provider driver names and descriptions. '
                      'Must match the driver name in the '
                      'octavia.api.drivers entrypoint. Example: '
                      'amphora:The Octavia Amphora driver.,'
                      'octavia:Deprecated alias of the Octavia '
                      'Amphora driver.,'
                      'amphorav2:The Octavia Amphora driver that uses '
                      'taskflow jobboard persistence.'),
                default={'amphora': 'The Octavia Amphora driver.',
                         'amphorav2': 'The Octavia Amphora driver that uses '
                                      'taskflow jobboard persistence.',
                         'octavia': 'Deprecated alias of the Octavia Amphora '
                         'driver.'}),
    cfg.StrOpt('loadbalancer_topology',
               default=const.SINGLE,
               choices=const.SUPPORTED_LB_TOPOLOGIES,
               help='Load balancer topology configuration.'),
    cfg.DictOpt('expected_flavor_capability',
                help=('Defines a provider flavor capability that is expected '
                      'to be present in the selected provider under test. '
                      'It is specified in a "name": "description" dict. '
                      'Example: {"loadbalancer_topology": "The load balancer '
                      'topology. One of: SINGLE - One amphora per load '
                      'balancer. ACTIVE_STANDBY - Two amphora per load '
                      'balancer."}'),
                default={'loadbalancer_topology': 'The load balancer '
                         'topology. One of: SINGLE - One amphora per load '
                         'balancer. ACTIVE_STANDBY - Two amphora per load '
                         'balancer.'}),
    cfg.DictOpt('expected_availability_zone_capability',
                help=('Defines a provider availability zone capability that '
                      'is expected to be present in the selected provider '
                      'under test. It is specified in a "name": "description" '
                      'dict. Example: {"compute_zone": "The compute '
                      'availability zone."}'),
                default={'compute_zone': 'The compute availability zone.'}),
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
    cfg.StrOpt('default_router',
               default='router1',
               help='The default router connected to the public network.'),
    cfg.StrOpt('default_ipv6_subnetpool',
               default='shared-default-subnetpool-v6',
               help='The default IPv6 subnetpool to use when creating the '
                    'IPv6 VIP subnet.'),
    # Amphora specific options
    cfg.StrOpt('amphora_ssh_user',
               default='ubuntu',
               help='The amphora SSH user.'),
    cfg.StrOpt('amphora_ssh_key',
               default='/etc/octavia/.ssh/octavia_ssh_key',
               help='The amphora SSH key file.'),
    # Environment specific options
    # These are used to accomodate clouds with specific limitations
    cfg.IntOpt('random_server_name_length',
               default=0,
               help='If non-zero, generate a random name of the length '
                    'provided for each server, in the format "m[A-Z0-9]*". '),
    cfg.StrOpt('availability_zone',
               default=None,
               help='Availability zone to use for creating servers.'),
    cfg.StrOpt('availability_zone2',
               default=None,
               help='A second availability zone to use for creating servers.'),
    cfg.StrOpt('availability_zone3',
               default=None,
               help='A third availability zone to use for creating servers.'),
    cfg.BoolOpt('test_reuse_connection', default=True,
                help='Reuse TCP connections while testing LB with '
                     'HTTP members (keep-alive).'),
    # Log offloading specific options
    cfg.StrOpt('tenant_flow_log_file',
               default='/var/log/octavia-tenant-traffic.log',
               help='File path, on the tempest system, to the tenant flow '
                    'log file.'),
    cfg.StrOpt('amphora_admin_log_file',
               default='/var/log/octavia-amphora.log',
               help='File path, on the tempest system, to the amphora admin '
                    'log file.'),
    cfg.StrOpt('test_server_path',
               default='/opt/octavia-tempest-plugin/test_server.bin',
               help='Filesystem path to the test web server that will be '
                    'installed in the web server VMs.'),
    # RBAC related options
    # Note: Also see the enforce_scope section (from tempest) for Octavia API
    #       scope checking setting.
    cfg.BoolOpt('enforce_new_defaults',
                default=False,
                help='Does the load-balancer service API policies enforce '
                     'the new keystone default roles? This configuration '
                     'value should be same as octavia.conf: '
                     '[oslo_policy].enforce_new_defaults option.'),
]

lb_feature_enabled_group = cfg.OptGroup(name='loadbalancer-feature-enabled',
                                        title='Enabled/Disabled LB features')
LBFeatureEnabledGroup = [
    cfg.BoolOpt('not_implemented_is_error',
                default=True,
                help="When True, not-implemented responses from the API are "
                     "considered an error and test failure. This should be "
                     "used when a driver should support all of the Octavia "
                     "API features, such as the reference driver."),
    cfg.BoolOpt('health_monitor_enabled',
                default=True,
                help="Whether Health Monitor is available with provider "
                     "driver or not."),
    cfg.BoolOpt('terminated_tls_enabled',
                default=True,
                help="Whether TLS termination is available with provider "
                     "driver or not."),
    cfg.BoolOpt('l7_protocol_enabled',
                default=True,
                help="Whether L7 Protocols are available with the provider "
                     "driver or not."),
    cfg.BoolOpt('pool_algorithms_enabled',
                default=True,
                help="Whether pool algorithms are available with provider"
                     "driver or not."),
    cfg.StrOpt('l4_protocol',
               default="TCP",
               help="The type of L4 Protocol which is supported with the "
                    "provider driver."),
    cfg.BoolOpt('spare_pool_enabled',
                default=False,
                help="Wether spare pool is available with amphora provider "
                "driver or not."),
    cfg.BoolOpt('session_persistence_enabled',
                default=True,
                help="Whether session persistence is supported with the "
                     "provider driver."),
    cfg.BoolOpt('log_offload_enabled', default=False,
                help="Whether the log offload tests will run. These require "
                     "the tempest instance have access to the log files "
                     "specified in the tempest configuration."),
]

# Extending this enforce_scope group defined in tempest
enforce_scope_group = cfg.OptGroup(name="enforce_scope",
                                   title="OpenStack Services with "
                                         "enforce scope")
EnforceScopeGroup = [
    cfg.BoolOpt('octavia',
                default=False,
                help='Does the load-balancer service API policies enforce '
                     'scope? This configuration value should be same as '
                     'octavia.conf: [oslo_policy].enforce_scope option.'),
]
