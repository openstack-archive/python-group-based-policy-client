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

import logging
import sys

from gbpclient.gbp.v2_0 import groupbasedpolicy as gbp
from gbpclient.tests.unit import test_cli20


class CLITestV20ExternalPolicyJSON(test_cli20.CLITestV20Base):

    LOG = logging.getLogger(__name__)

    def setUp(self):
        super(CLITestV20ExternalPolicyJSON, self).setUp()

    def test_create_external_policy_with_mandatory_params(self):
        """external-policy-create with all mandatory params."""
        resource = 'external_policy'
        cmd = gbp.CreateExternalPolicy(test_cli20.MyApp(sys.stdout), None)
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

    def test_create_external_policy_with_all_params(self):
        """external-policy-create with all params."""
        resource = 'external_policy'
        cmd = gbp.CreateExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        tenant_id = 'mytenant'
        description = 'My External Policy'
        my_id = 'someid'
        provided_policy_rule_sets = "prs1=true,prs2=true"
        consumed_policy_rule_sets = "prs3=true,prs4=true"
        external_segments = "ES1,ES2"
        shared = 'true'
        args = ['--tenant-id', tenant_id,
                '--description', description,
                '--provided-policy-rule-sets', provided_policy_rule_sets,
                '--consumed-policy-rule-sets', consumed_policy_rule_sets,
                '--external-segments', external_segments,
                '--shared', shared,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id,
                                   description=description,
                                   provided_policy_rule_sets=
                                   {'prs1': 'true', 'prs2': 'true'},
                                   consumed_policy_rule_sets=
                                   {'prs3': 'true', 'prs4': 'true'},
                                   external_segments=
                                   ['ES1', 'ES2'],
                                   shared=shared)

    def test_list_external_policies(self):
        """external-policy-list."""
        resource = 'external_policies'
        cmd = gbp.ListExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resource, cmd, True)

    def test_show_external_policy_name(self):
        """external-policy-show."""
        resource = 'external_policy'
        cmd = gbp.ShowExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_update_external_policy(self):
        "external-policy-update myid --name myname --tags a b."
        resource = 'external_policy'
        cmd = gbp.UpdateExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_external_policy_with_all_params(self):
        resource = 'external_policy'
        cmd = gbp.UpdateExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        description = 'My External Policy'
        my_id = 'someid'
        provided_policy_rule_sets = "prs1=true,prs2=true"
        consumed_policy_rule_sets = "prs3=true,prs4=true"
        external_segments = "ES1,ES2"
        shared = 'true'
        args = ['--name', name,
                '--description', description,
                '--provided-policy-rule-sets', provided_policy_rule_sets,
                '--consumed-policy-rule-sets', consumed_policy_rule_sets,
                '--external-segments', external_segments,
                '--shared', shared,
                my_id]
        params = {
            'name': name,
            'description': description,
            'provided_policy_rule_sets': {'prs1': 'true', 'prs2': 'true'},
            'consumed_policy_rule_sets': {'prs3': 'true', 'prs4': 'true'},
            'external_segments': ['ES1', 'ES2'],
            'shared': shared
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_update_external_policy_unset_external_segment(self):
        resource = 'external_policy'
        cmd = gbp.UpdateExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        my_id = 'someid'
        external_segments = ""
        args = ['--external-segments', external_segments, my_id]
        params = {'external_segments': []}
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_update_external_policy_unset_prs(self):
        resource = 'external_policy'
        cmd = gbp.UpdateExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        my_id = 'someid'
        provided_policy_rule_sets = ""
        consumed_policy_rule_sets = ""
        args = ['--provided-policy-rule-sets', provided_policy_rule_sets,
                '--consumed-policy-rule-sets', consumed_policy_rule_sets,
                my_id]
        params = {
            'provided_policy_rule_sets': {},
            'consumed_policy_rule_sets': {},
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_delete_external_policy_name(self):
        """external-policy-delete."""
        resource = 'external_policy'
        cmd = gbp.DeleteExternalPolicy(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
