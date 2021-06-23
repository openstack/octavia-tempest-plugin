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

import os

from tempest import config
from tempest.test_discover import plugins

from octavia_tempest_plugin import config as project_config
from octavia_tempest_plugin.services.load_balancer import v2 as lb_v2_services


class OctaviaTempestPlugin(plugins.TempestPlugin):

    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "octavia_tempest_plugin/tests"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        config.register_opt_group(conf, project_config.service_available_group,
                                  project_config.ServiceAvailableGroup)
        config.register_opt_group(conf, project_config.octavia_group,
                                  project_config.OctaviaGroup)
        config.register_opt_group(conf,
                                  project_config.lb_feature_enabled_group,
                                  project_config.LBFeatureEnabledGroup)
        config.register_opt_group(conf, project_config.enforce_scope_group,
                                  project_config.EnforceScopeGroup)

    def get_opt_lists(self):
        return [
            (project_config.service_available_group.name,
             project_config.ServiceAvailableGroup),
            (project_config.octavia_group.name,
             project_config.OctaviaGroup),
            (project_config.lb_feature_enabled_group.name,
             project_config.LBFeatureEnabledGroup)
        ]

    def get_service_clients(self):
        octavia_config = config.service_client_config(
            project_config.octavia_group.name
        )

        params = {
            'name': 'load_balancer_v2',
            'service_version': 'load-balancer.v2',
            'module_path': 'octavia_tempest_plugin.services.load_balancer.v2',
            'client_names': lb_v2_services.__all__,
        }
        params.update(octavia_config)

        return [params]
