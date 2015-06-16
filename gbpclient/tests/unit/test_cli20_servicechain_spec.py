# Copyright 2012 OpenStack Foundation.
# All Rights Reserved
#
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

from gbpclient.gbp.v2_0 import servicechain
from gbpclient.tests.unit import test_cli20


class CLITestV20ServiceChainSpecJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20ServiceChainSpecJSON, self).setUp()

    def test_create_servicechain_spec_with_mandatory_params(self):
        """service-chain-spec-create with all mandatory params."""
        resource = 'servicechain_spec'
        cmd = servicechain.CreateServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                  None)
        name = 'my-name'
        tenant_id = 'my-tenant'
        my_id = 'my-id'
        args = ['--tenant-id', tenant_id, name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id)

    def test_create_servicechain_spec_with_all_params(self):
        """service-chain-spec-create with all params."""
        resource = 'servicechain_spec'
        cmd = servicechain.CreateServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                  None)
        name = 'my-name'
        nodes_arg = 'node1 node2'
        nodes_res = ['node1', 'node2']
        tenant_id = 'my-tenant'
        description = 'My Service Chain Spec'
        my_id = 'my-id'
        shared = 'True'
        args = ['--nodes', nodes_arg,
                '--tenant-id', tenant_id,
                '--description', description,
                '--shared', shared,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   nodes=nodes_res, tenant_id=tenant_id,
                                   description=description, shared=True)

    def test_list_servicechain_specs(self):
        """service-chain-spec-list."""
        resources = 'servicechain_specs'
        cmd = servicechain.ListServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources(resources, cmd, True)

    def test_list_servicechain_specs_pagination(self):
        """service-chain-spec-list."""
        resources = 'servicechain_specs'
        cmd = servicechain.ListServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_servicechain_specs_sort(self):
        """service-chain-spec-list --sort-key name --sort-key id --sort-key asc
        --sort-key desc
        """
        resources = 'servicechain_specs'
        cmd = servicechain.ListServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_servicechain_specs_limit(self):
        """service-chain-spec-list -P."""
        resources = 'servicechain_specs'
        cmd = servicechain.ListServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_servicechain_spec_id(self):
        """service-chain-spec-show test_id."""
        resource = 'servicechain_spec'
        cmd = servicechain.ShowServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_servicechain_spec_id_name(self):
        """service-chain-spec-show."""
        resource = 'servicechain_spec'
        cmd = servicechain.ShowServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_servicechain_spec(self):
        """service-chain-spec-update  myid --name myname --tags a b."""
        resource = 'servicechain_spec'
        cmd = servicechain.UpdateServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                  None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_servicechain_node_with_all_params(self):
        resource = 'servicechain_spec'
        cmd = servicechain.UpdateServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                  None)
        nodes_arg = 'node1 node2'
        nodes_res = ['node1', 'node2']
        body = {
            'name': 'new_name',
            'description': 'new_description',
            'nodes': nodes_res,
            'shared': True,
        }
        args = ['myid', '--name', 'new_name',
                '--description', 'new_description',
                '--nodes', nodes_arg,
                '--shared', 'True']
        self._test_update_resource(resource, cmd, 'myid', args, body)

    def test_delete_servicechain_spec(self):
        """service-chain-spec-delete my-id."""
        resource = 'servicechain_spec'
        cmd = servicechain.DeleteServiceChainSpec(test_cli20.MyApp(sys.stdout),
                                                  None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
