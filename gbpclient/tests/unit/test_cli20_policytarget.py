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


class CLITestV20PolicyTargetJSON(test_cli20.CLITestV20Base):

    LOG = logging.getLogger(__name__)

    def setUp(self):
        super(CLITestV20PolicyTargetJSON, self).setUp()

    def test_create_policy_target_with_mandatory_params(self):
        resource = 'policy_target'
        cmd = gbp.CreatePolicyTarget(test_cli20.MyApp(sys.stdout), None)
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

    def test_list_policy_targets(self):
        resource = 'policy_targets'
        cmd = gbp.ListPolicyTarget(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resource, cmd, True)

    def test_show_policy_target_name(self):
        resource = 'policy_target'
        cmd = gbp.ShowPolicyTarget(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_update_policy_target(self):
        resource = 'policy_target'
        cmd = gbp.UpdatePolicyTarget(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_delete_policy_target_name(self):
        resource = 'policy_target'
        cmd = gbp.DeletePolicyTarget(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
