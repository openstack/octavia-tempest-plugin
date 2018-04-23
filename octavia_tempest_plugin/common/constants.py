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

# API valid fields
SHOW_LOAD_BALANCER_RESPONSE_FIELDS = (
    ADMIN_STATE_UP, CREATED_AT, DESCRIPTION, FLAVOR_ID, ID, LISTENERS, NAME,
    OPERATING_STATUS, POOLS, PROJECT_ID, PROVIDER, PROVISIONING_STATUS,
    UPDATED_AT, VIP_ADDRESS, VIP_NETWORK_ID, VIP_PORT_ID, VIP_SUBNET_ID,
    VIP_QOS_POLICY_ID)

# Other constants
ACTIVE = 'ACTIVE'
ADMIN_STATE_UP_TRUE = 'true'
ASC = 'asc'
DELETED = 'DELETED'
DESC = 'desc'
FIELDS = 'fields'
OFFLINE = 'OFFLINE'
ONLINE = 'ONLINE'
SORT = 'sort'

# RBAC options
ADVANCED = 'advanced'
OWNERADMIN = 'owner_or_admin'
NONE = 'none'
