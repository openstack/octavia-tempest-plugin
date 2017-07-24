#   Copyright 2017 GoDaddy
#   Copyright 2017 Catalyst IT Ltd
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

import os

from tempest import config
from tempest.test_discover import plugins

from octavia_tempest_plugin import config as project_config


class OctaviaTempestPlugin(plugins.TempestPlugin):
    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "octavia_tempest_plugin/tests"
        full_test_dir = os.path.join(base_path, test_dir)

        return full_test_dir, base_path

    def register_opts(self, conf):
        conf.register_opt(
            project_config.service_option, group='service_available'
        )
        conf.register_group(project_config.octavia_group)
        conf.register_opts(project_config.OctaviaGroup,
                           group=project_config.octavia_group.name)

    def get_opt_lists(self):
        return [
            ('service_available', [project_config.service_option]),
            (project_config.octavia_group.name, project_config.OctaviaGroup)
        ]

    def get_service_clients(self):
        octavia_config = config.service_client_config(
            project_config.octavia_group.name
        )
        module_path = 'octavia_tempest_plugin.services.v2.loadbalancer_client'

        params = {
            'name': 'octavia_v2',
            'service_version': 'octavia.v2',
            'module_path': module_path,
            'client_names': ['LoadbalancerClient'],
        }
        params.update(octavia_config)

        return [params]
