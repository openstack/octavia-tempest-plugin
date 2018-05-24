# Copyright 2018 Rackspace US Inc.  All rights reserved.
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

# API field names
ACTIVE_CONNECTIONS = 'active_connections'
ADMIN_STATE_UP = 'admin_state_up'
BYTES_IN = 'bytes_in'
BYTES_OUT = 'bytes_out'
CREATED_AT = 'created_at'
DESCRIPTION = 'description'
FLAVOR_ID = 'flavor_id'
ID = 'id'
LISTENERS = 'listeners'
LOADBALANCER = 'loadbalancer'
NAME = 'name'
OPERATING_STATUS = 'operating_status'
POOLS = 'pools'
PROJECT_ID = 'project_id'
PROVIDER = 'provider'
PROVISIONING_STATUS = 'provisioning_status'
REQUEST_ERRORS = 'request_errors'
TOTAL_CONNECTIONS = 'total_connections'
UPDATED_AT = 'updated_at'
VIP_ADDRESS = 'vip_address'
VIP_NETWORK_ID = 'vip_network_id'
VIP_PORT_ID = 'vip_port_id'
VIP_SUBNET_ID = 'vip_subnet_id'
VIP_QOS_POLICY_ID = 'vip_qos_policy_id'
PROTOCOL = 'protocol'
PROTOCOL_PORT = 'protocol_port'
LOADBALANCER_ID = 'loadbalancer_id'
CONNECTION_LIMIT = 'connection_limit'
INSERT_HEADERS = 'insert_headers'
X_FORWARDED_FOR = 'X-Forwarded-For'
X_FORWARDED_PORT = 'X-Forwarded-Port'
TIMEOUT_CLIENT_DATA = 'timeout_client_data'
TIMEOUT_MEMBER_CONNECT = 'timeout_member_connect'
TIMEOUT_MEMBER_DATA = 'timeout_member_data'
TIMEOUT_TCP_INSPECT = 'timeout_tcp_inspect'
DEFAULT_TLS_CONTAINER_REF = 'default_tls_container_ref'
SNI_CONTAINER_REFS = 'sni_container_refs'
DEFAULT_POOL_ID = 'default_pool_id'
L7_POLICIES = 'l7_policies'

LB_ALGORITHM = 'lb_algorithm'
LB_ALGORITHM_ROUND_ROBIN = 'ROUND_ROBIN'
LB_ALGORITHM_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_ALGORITHM_SOURCE_IP = 'SOURCE_IP'
SESSION_PERSISTENCE = 'session_persistence'
LISTENER_ID = 'listener_id'
LOADBALANCERS = 'loadbalancers'

POOL_ID = 'pool_id'
ADDRESS = 'address'
WEIGHT = 'weight'
BACKUP = 'backup'
SUBNET_ID = 'subnet_id'
MONITOR_ADDRESS = 'monitor_address'
MONITOR_PORT = 'monitor_port'

DELAY = 'delay'
TIMEOUT = 'timeout'
MAX_RETRIES = 'max_retries'
MAX_RETRIES_DOWN = 'max_retries_down'
HTTP_METHOD = 'http_method'
URL_PATH = 'url_path'
EXPECTED_CODES = 'expected_codes'

# Other constants
ACTIVE = 'ACTIVE'
ADMIN_STATE_UP_TRUE = 'true'
ASC = 'asc'
DELETED = 'DELETED'
DESC = 'desc'
FIELDS = 'fields'
OFFLINE = 'OFFLINE'
ONLINE = 'ONLINE'
NO_MONITOR = 'NO_MONITOR'
ERROR = 'ERROR'
SORT = 'sort'

# Protocols
HTTP = 'HTTP'
HTTPS = 'HTTPS'
TCP = 'TCP'

# HTTP Methods
GET = 'GET'
POST = 'POST'
PUT = 'PUT'
DELETE = 'DELETE'

# HM Types
HEALTH_MONITOR_PING = 'PING'
HEALTH_MONITOR_TCP = 'TCP'
HEALTH_MONITOR_HTTP = 'HTTP'
HEALTH_MONITOR_HTTPS = 'HTTPS'
HEALTH_MONITOR_TLS_HELLO = 'TLS-HELLO'

# Session Persistence
TYPE = 'type'
COOKIE_NAME = 'cookie_name'
SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'

# L7Policy options
POSITION = 'position'
REDIRECT_URL = 'redirect_url'
REDIRECT_POOL_ID = 'redirect_pool_id'

ACTION = 'action'
REDIRECT_TO_POOL = 'REDIRECT_TO_POOL'
REDIRECT_TO_URL = 'REDIRECT_TO_URL'
REJECT = 'REJECT'

# RBAC options
ADVANCED = 'advanced'
OWNERADMIN = 'owner_or_admin'
NONE = 'none'

# API valid fields
SHOW_LOAD_BALANCER_RESPONSE_FIELDS = (
    ADMIN_STATE_UP, CREATED_AT, DESCRIPTION, FLAVOR_ID, ID, LISTENERS, NAME,
    OPERATING_STATUS, POOLS, PROJECT_ID, PROVIDER, PROVISIONING_STATUS,
    UPDATED_AT, VIP_ADDRESS, VIP_NETWORK_ID, VIP_PORT_ID, VIP_SUBNET_ID,
    VIP_QOS_POLICY_ID)

SHOW_LISTENER_RESPONSE_FIELDS = (
    ID, NAME, DESCRIPTION, PROVISIONING_STATUS, OPERATING_STATUS,
    ADMIN_STATE_UP, PROTOCOL, PROTOCOL_PORT, CONNECTION_LIMIT,
    DEFAULT_TLS_CONTAINER_REF, SNI_CONTAINER_REFS, PROJECT_ID,
    DEFAULT_POOL_ID, L7_POLICIES, INSERT_HEADERS, CREATED_AT, UPDATED_AT,
    TIMEOUT_CLIENT_DATA, TIMEOUT_MEMBER_CONNECT, TIMEOUT_MEMBER_DATA,
    TIMEOUT_TCP_INSPECT
)

SHOW_POOL_RESPONSE_FIELDS = (
    ID, NAME, DESCRIPTION, PROVISIONING_STATUS, OPERATING_STATUS,
    ADMIN_STATE_UP, PROTOCOL, LB_ALGORITHM, SESSION_PERSISTENCE,
    CREATED_AT, UPDATED_AT
)

SHOW_MEMBER_RESPONSE_FIELDS = (
    ID, NAME, PROVISIONING_STATUS, OPERATING_STATUS, ADMIN_STATE_UP,
    ADDRESS, PROTOCOL_PORT, WEIGHT, BACKUP, MONITOR_PORT, MONITOR_ADDRESS
)

SHOW_HEALTHMONITOR_RESPONSE_FIELDS = (
    ID, NAME, PROVISIONING_STATUS, OPERATING_STATUS, ADMIN_STATE_UP,
    TYPE, DELAY, TIMEOUT, MAX_RETRIES, MAX_RETRIES_DOWN, HTTP_METHOD,
    URL_PATH, EXPECTED_CODES, CREATED_AT, UPDATED_AT
)

SHOW_L7POLICY_RESPONSE_FIELDS = (
    ID, NAME, DESCRIPTION, PROVISIONING_STATUS, OPERATING_STATUS,
    ADMIN_STATE_UP, LISTENER_ID, POSITION, ACTION, REDIRECT_URL,
    REDIRECT_POOL_ID, CREATED_AT, UPDATED_AT
)
