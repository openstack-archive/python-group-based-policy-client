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

    def test_create_policy_target_with_segmentation_labels(self):
        """policy-target-create with segmentation labels."""
        resource = 'policy_target'
        cmd = gbp.CreatePolicyTarget(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        tenant_id = 'my-tenant'
        name = 'my-name'
        description = 'pt description'
        policy_target_group_id = 'policy_target_group_id'
        segmentation_labels = "label1,label2"
        args = [name,
                '--tenant-id', tenant_id,
                '--description', description,
                '--policy-target-group-id', policy_target_group_id,
                '--segmentation-labels', segmentation_labels]
        position_names = ['name', 'description', 'policy_target_group_id',
                          'segmentation_labels']
        position_values = [name, description, policy_target_group_id,
                           ['label1', 'label2']]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id)

    def test_list_policy_targets(self):
        resource = 'policy_targets'
        cmd = gbp.ListPolicyTarget(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resource, cmd, True)

    def test_list_policy_targets_with_fixed_ips(self):
        resources = "policy_targets"
        cmd = gbp.ListPolicyTarget(test_cli20.MyApp(sys.stdout), None)
        fixed_ips = [{"subnet_id": "30422057-d6df-4c90-8314-aefb5e326666",
                      "ip_address": "10.0.0.12"},
                     {"subnet_id": "30422057-d6df-4c90-8314-aefb5e326666",
                      "ip_address": "10.0.0.4"}]
        contents = [{'name': 'name1', 'fixed_ips': fixed_ips}]
        self._test_list_resources(resources, cmd, True,
                                  response_contents=contents)

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

    def test_update_policy_target_fixed_ip(self):
        resource = 'policy_target'
        cmd = gbp.UpdatePolicyTarget(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        subnet_id = 'subnet_id'
        ip_addr = '123.123.123.123'
        args = [myid,
                '--fixed-ip',
                "subnet_id=%(subnet_id)s,ip_address=%(ip_addr)s" %
                {'subnet_id': subnet_id,
                 'ip_addr': ip_addr}]
        updated_fields = {"fixed_ips": [{'subnet_id': subnet_id,
                                         'ip_address': ip_addr}]}
        self._test_update_resource(resource, cmd, myid, args, updated_fields)

    def test_update_policy_target_with_segmentation_labels(self):
        """policy-target-update with segmentation labels."""
        resource = 'policy_target'
        cmd = gbp.UpdatePolicyTarget(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        segmentation_labels = "label3,label4"
        args = [my_id,
                '--segmentation-labels', segmentation_labels]
        updated_fields = {"segmentation_labels": ['label3', 'label4']}
        self._test_update_resource(resource, cmd, my_id, args,
                                   updated_fields)

    def test_delete_policy_target_name(self):
        resource = 'policy_target'
        cmd = gbp.DeletePolicyTarget(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
