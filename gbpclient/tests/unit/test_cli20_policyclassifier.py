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


class CLITestV20PolicyClassifierJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20PolicyClassifierJSON, self).setUp()

    def test_create_policy_classifier_with_mandatory_params(self):
        """grouppolicy-policy-classifier-create with all mandatory params."""
        resource = 'policy_classifier'
        cmd = gbp.CreatePolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        name = 'my-name'
        direction = 'bi'
        tenant_id = 'my-tenant'
        my_id = 'my-id'
        args = ['--tenant-id', tenant_id, '--direction', direction,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id, direction=direction)

    def test_create_policy_classifier_with_all_params(self):
        """grouppolicy-policy-classifier-create with all params."""
        resource = 'policy_classifier'
        cmd = gbp.CreatePolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        name = 'my-name'
        tenant_id = 'my-tenant'
        description = 'My PolicyClassifier'
        my_id = 'my-id'
        port_range = '10-80'
        direction = 'in'
        shared = 'true'
        for protocol in ['tcp', 'icmp', 'udp', '50']:
            args = ['--tenant-id', tenant_id,
                    '--description', description,
                    '--protocol', protocol,
                    '--port-range', port_range,
                    '--direction', direction,
                    '--shared', shared,
                    name]
            position_names = ['name', ]
            position_values = [name, ]
            self._test_create_resource(resource, cmd, name, my_id, args,
                                       position_names, position_values,
                                       tenant_id=tenant_id,
                                       description=description,
                                       protocol=protocol,
                                       port_range=port_range,
                                       direction=direction, shared=shared)

    def test_list_policy_classifiers(self):
        """grouppolicy-policy-classifier-list."""
        resources = 'policy_classifiers'
        cmd = gbp.ListPolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_policy_classifiers_pagination(self):
        """grouppolicy-policy-classifier-list."""
        resources = 'policy_classifiers'
        cmd = gbp.ListPolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_policy_classifiers_sort(self):
        """grouppolicy-policy-classifier-list --sort-key name --sort-key id
        --sort-key asc --sort-key desc
        """
        resources = 'policy_classifiers'
        cmd = gbp.ListPolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_policy_classifiers_limit(self):
        """grouppolicy-policy-classifier-list -P."""
        resources = 'policy_classifiers'
        cmd = gbp.ListPolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_policy_classifier_id(self):
        """grouppolicy-policy-classifier-show test_id."""
        resource = 'policy_classifier'
        cmd = gbp.ShowPolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_policy_classifier_id_name(self):
        """grouppolicy-policy-classifier-show."""
        resource = 'policy_classifier'
        cmd = gbp.ShowPolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_policy_classifier(self):
        """grouppolicy-policy-classifier-update  myid --name myname --tags a b.
        """
        resource = 'policy_classifier'
        cmd = gbp.UpdatePolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_policy_classifier_with_allparams(self):
        resource = 'policy_classifier'
        port_range = '10-80'
        direction = 'in'
        cmd = gbp.UpdatePolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        my_id = 'someid'
        shared = 'true'
        for protocol in ['tcp', 'icmp', 'udp', '50']:
            body = {
                'protocol': protocol,
                'port_range': port_range,
                'direction': direction,
                'shared': shared
            }
            args = [my_id,
                    '--protocol', protocol,
                    '--port-range', port_range,
                    '--direction', direction,
                    '--shared', shared, ]
            self._test_update_resource(resource, cmd, my_id, args, body)

    def test_delete_policy_classifier(self):
        """grouppolicy-policy-classifier-delete my-id."""
        resource = 'policy_classifier'
        cmd = gbp.DeletePolicyClassifier(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
