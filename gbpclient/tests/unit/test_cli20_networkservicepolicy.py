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


class CLITestV20NetworkServicePolicyJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20NetworkServicePolicyJSON, self).setUp()

    def test_create_nsp_with_mandatory_params(self):
        """network-service-policy-create with mandatory params."""
        resource = 'network_service_policy'
        cmd = gbp.CreateNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                             None)
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

    def test_create_network_service_policy_with_all_params(self):
        """network-service-policy-create with all params."""
        resource = 'network_service_policy'
        cmd = gbp.CreateNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                             None)
        name = 'myname'
        tenant_id = 'mytenant'
        description = 'Mynsp'
        my_id = 'someid'
        network_svc_params = "type=ip_single,name=vip,value=self_subnet"
        shared = 'True'
        args = ['--tenant_id', tenant_id,
                '--description', description,
                '--network-service-params', network_svc_params,
                '--shared', shared,
                name]
        position_names = ['name', 'description', 'network_service_params']
        net_params = [{"type": "ip_single", "name": "vip",
                       "value": "self_subnet"}]
        position_values = [name, description, net_params]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id, shared=True)

    def test_list_network_service_policies(self):
        """network-sercvice-policy-list."""
        resources = 'network_service_policies'
        cmd = gbp.ListNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                           None)
        self._test_list_resources(resources, cmd, True)

    def test_list_network_service_policies_with_pagination(self):
        """network-sercvice-policy-list."""
        resources = 'network_service_policies'
        cmd = gbp.ListNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                           None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_network_sercice_policies_sort(self):
        """network-service-policy-list --sort-key name --sort-key id
        --sort-key asc --sort-key desc
        """
        resources = 'network_service_policies'
        cmd = gbp.ListNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                           None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_network_service_polices_limit(self):
        """network-service-policy-list -P."""
        resources = 'network_service_policies'
        cmd = gbp.ListNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                           None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_network_service_policy_id(self):
        """network-service-policy-show test_id."""
        resource = 'network_service_policy'
        cmd = gbp.ShowNetworkServicePolicy(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_network_service_policy_id_name(self):
        """network-service-policy-show."""
        resource = 'network_service_policy'
        cmd = gbp.ShowNetworkServicePolicy(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_network_service_policy(self):
        """network-service-policy-update  myid --name myname --tags a b."""
        resource = 'network_service_policy'
        cmd = gbp.UpdateNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                             None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_network_service_policy_with_allparams(self):
        """network-service-policy-update with all params."""
        resource = 'network_service_policy'
        cmd = gbp.UpdateNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                             None)
        name = 'nsp'
        description = 'nsp description'
        my_id = 'someid'
        network_svc_params = "type=ip_single,name=vip,value=self_subnet"
        shared = 'True'
        args = [my_id,
                '--name', name,
                '--description', description,
                '--network-service-params', network_svc_params,
                '--shared', shared,
                '--request-format', 'json']
        params = {
            'name': name,
            'description': description,
            'network_service_params': [{"type": "ip_single", "name": "vip",
                                        "value": "self_subnet"}],
            'shared': True
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_delete_network_service_policy(self):
        """network-service-policy-delete my-id."""
        resource = 'network_service_policy'
        cmd = gbp.DeleteNetworkServicePolicy(test_cli20.MyApp(sys.stdout),
                                             None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
