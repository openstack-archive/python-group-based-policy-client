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


class CLITestV20PolicyTargetGroupJSON(test_cli20.CLITestV20Base):

    LOG = logging.getLogger(__name__)

    def setUp(self):
        super(CLITestV20PolicyTargetGroupJSON, self).setUp()

    def test_create_policy_target_group_with_mandatory_params(self):
        """policy-target-group-create with all mandatory params."""
        # log and debugger doesn't work in the client.
        # import pdb; pdb.set_trace()
        self.LOG.info("called")
        resource = 'policy_target_group'
        cmd = gbp.CreatePolicyTargetGroup(test_cli20.MyApp(sys.stdout), None)
        # name = 'my-policy-target-group'
        name = 'my-name'
        tenant_id = 'my-tenant'
        my_id = 'my-id'
        # provided_policy_rule_sets = {}
        # provided_policy_rule_sets = None
        args = ['--tenant-id', tenant_id,
                # '--provided_policy_rule_sets', provided_policy_rule_sets,
                name]
        # args = [name]
        position_names = ['name', ]
        position_values = [name, ]

        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id)
