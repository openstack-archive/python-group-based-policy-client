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
#

from neutronclient.tests.unit import test_cli20_purge


class CLITestV20Purge(test_cli20_purge.CLITestV20Purge):
    def setUp(self):
        super(CLITestV20Purge, self).setUp()
        self.resource_types = ['policy_target', 'policy_target_group',
                               'l2_policy', 'l3_policy', 'external_policy',
                               'nat_pool', 'external_segment',
                               'policy_rule_set', 'policy_rule',
                               'policy_classifier', 'policy_action',
                               'network_service_policy',
                               'servicechain_instance', 'servicechain_spec',
                               'servicechain_node', 'service_profile',
                               'application_policy_group']
