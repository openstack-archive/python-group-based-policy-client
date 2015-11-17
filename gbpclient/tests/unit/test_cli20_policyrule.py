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

import sys

from gbpclient.gbp.v2_0 import groupbasedpolicy as gbp
from gbpclient.tests.unit import test_cli20


class CLITestV20PolicyRuleJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20PolicyRuleJSON, self).setUp()

    def test_create_policy_rule_with_mandatory_params(self):
        """grouppolicy-policy-rule-create with all mandatory params."""
        resource = 'policy_rule'
        cmd = gbp.CreatePolicyRule(test_cli20.MyApp(sys.stdout), None)
        name = 'my-name'
        tenant_id = 'my-tenant'
        my_id = 'my-id'
        args = ['--tenant-id', tenant_id,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id)

    def test_create_policy_rule_with_all_params(self):
        """grouppolicy-policy-rule-create with all params."""
        resource = 'policy_rule'
        cmd = gbp.CreatePolicyRule(test_cli20.MyApp(sys.stdout), None)
        name = 'my-name'
        tenant_id = 'my-tenant'
        description = 'My PolicyRule'
        my_id = 'my-id'
        enabled = "true"
        policy_classifier_id = 'pc-id'
        policy_actions_res = ["pa1", "pa2"]
        policy_actions_arg = "pa1,pa2"
        shared = 'true'
        args = ['--tenant-id', tenant_id,
                '--description', description,
                '--enabled', enabled,
                '--classifier', policy_classifier_id,
                '--actions', policy_actions_arg,
                '--shared', shared,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id,
                                   description=description,
                                   enabled=enabled,
                                   policy_classifier_id=policy_classifier_id,
                                   policy_actions=policy_actions_res,
                                   shared=shared)

    def test_list_policy_rules(self):
        """grouppolicy-policy-rule-list."""
        resources = 'policy_rules'
        cmd = gbp.ListPolicyRule(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_policy_rules_pagination(self):
        """grouppolicy-policy-rule-list."""
        resources = 'policy_rules'
        cmd = gbp.ListPolicyRule(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_policy_rules_sort(self):
        """grouppolicy-policy-rule-list --sort-key name --sort-key id
        --sort-key asc --sort-key desc
        """
        resources = 'policy_rules'
        cmd = gbp.ListPolicyRule(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_policy_rules_limit(self):
        """grouppolicy-policy-rule-list -P."""
        resources = 'policy_rules'
        cmd = gbp.ListPolicyRule(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_policy_classifier_id(self):
        """grouppolicy-policy-rule-show test_id."""
        resource = 'policy_rule'
        cmd = gbp.ShowPolicyRule(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_policy_classifier_id_name(self):
        """grouppolicy-policy-rule-show."""
        resource = 'policy_rule'
        cmd = gbp.ShowPolicyRule(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_policy_rule(self):
        """grouppolicy-policy-rule-update  myid --name myname --tags a b."""
        resource = 'policy_rule'
        cmd = gbp.UpdatePolicyRule(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_policy_rule_with_allparams(self):
        resource = 'policy_rule'
        enabled = "true"
        policy_classifier_id = 'pc-id'
        policy_actions_res = ["pa1", "pa2"]
        policy_actions_arg = "pa1,pa2"
        my_id = 'someid'
        shared = 'true'
        cmd = gbp.UpdatePolicyRule(test_cli20.MyApp(sys.stdout), None)
        body = {
            'policy_classifier_id': policy_classifier_id,
            'enabled': enabled,
            'policy_actions': policy_actions_res,
            'shared': shared
        }
        args = [my_id,
                '--enabled', enabled,
                '--classifier', policy_classifier_id,
                '--actions', policy_actions_arg,
                '--shared', shared, ]
        self._test_update_resource(resource, cmd, my_id, args, body)

    def test_update_policy_rule_unset_actions(self):
        resource = 'policy_rule'
        policy_actions_res = []
        policy_actions_arg = ""
        my_id = 'someid'
        cmd = gbp.UpdatePolicyRule(test_cli20.MyApp(sys.stdout), None)
        body = {'policy_actions': policy_actions_res}
        args = [my_id, '--actions', policy_actions_arg]
        self._test_update_resource(resource, cmd, my_id, args, body)

    def test_delete_policy_classifier(self):
        """grouppolicy-policy-rule-delete my-id."""
        resource = 'policy_rule'
        cmd = gbp.DeletePolicyRule(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
