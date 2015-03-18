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


class CLITestV20PolicyActionJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20PolicyActionJSON, self).setUp()

    def test_create_policy_action_with_mandatory_params(self):
        """grouppolicy-policy-action-create with all mandatory params."""
        resource = 'policy_action'
        cmd = gbp.CreatePolicyAction(test_cli20.MyApp(sys.stdout), None)
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

    def test_create_policy_action_with_all_params(self):
        """grouppolicy-policy-action-create with all params."""
        resource = 'policy_action'
        cmd = gbp.CreatePolicyAction(test_cli20.MyApp(sys.stdout), None)
        name = 'my-name'
        tenant_id = 'my-tenant'
        description = 'My PolicyAction'
        my_id = 'my-id'
        action_type = "allow"
        action_value = "1234"
        shared = 'True'
        args = ['--tenant-id', tenant_id,
                '--description', description,
                '--action-type', action_type,
                '--action-value', action_value,
                '--shared', shared,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id,
                                   description=description,
                                   action_type=action_type,
                                   action_value=action_value, shared=True)

    def test_list_policy_actions(self):
        """grouppolicy-policy-action-list."""
        resources = 'policy_actions'
        cmd = gbp.ListPolicyAction(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_policy_actions_pagination(self):
        """grouppolicy-policy-action-list."""
        resources = 'policy_actions'
        cmd = gbp.ListPolicyAction(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_policy_actions_sort(self):
        """grouppolicy-policy-action-list --sort-key name --sort-key id
        --sort-key asc --sort-key desc
        """
        resources = 'policy_actions'
        cmd = gbp.ListPolicyAction(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_policy_actions_limit(self):
        """grouppolicy-policy-action-list -P."""
        resources = 'policy_actions'
        cmd = gbp.ListPolicyAction(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_policy_action_id(self):
        """grouppolicy-policy-action-show test_id."""
        resource = 'policy_action'
        cmd = gbp.ShowPolicyAction(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_policy_action_id_name(self):
        """grouppolicy-policy-action-show."""
        resource = 'policy_action'
        cmd = gbp.ShowPolicyAction(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_policy_action(self):
        """grouppolicy-policy-action-update  myid --name myname --tags a b."""
        resource = 'policy_action'
        cmd = gbp.UpdatePolicyAction(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_policy_action_with_allparams(self):
        resource = 'policy_action'
        action_type = "allow"
        action_value = "1234"
        shared = 'True'
        my_id = 'someid'
        cmd = gbp.UpdatePolicyAction(test_cli20.MyApp(sys.stdout), None)
        body = {
            'action_type': action_type,
            'action_value': action_value,
            'shared': True
        }
        args = [my_id,
                '--action-type', action_type,
                '--action-value', action_value,
                '--shared', shared, ]
        self._test_update_resource(resource, cmd, my_id, args, body)

    def test_delete_policy_action(self):
        """grouppolicy-policy-action-delete my-id."""
        resource = 'policy_action'
        cmd = gbp.DeletePolicyAction(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
