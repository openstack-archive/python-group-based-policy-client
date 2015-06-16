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


class CLITestV20ServiceChainNodeJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20ServiceChainNodeJSON, self).setUp()

    def test_create_servicechain_node_with_mandatory_params(self):
        """service-chain-node-create with all mandatory params."""
        resource = 'servicechain_node'
        cmd = servicechain.CreateServiceChainNode(test_cli20.MyApp(sys.stdout),
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

    def test_create_servicechain_node_with_all_params(self):
        """service-chain-node-create with all params."""
        resource = 'servicechain_node'
        cmd = servicechain.CreateServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                  None)
        name = 'my-name'
        service_type = 'servicetype1'
        config = 'config1'
        tenant_id = 'my-tenant'
        description = 'My Service Chain Node'
        service_profile_id = 'my-service-profile'
        my_id = 'my-id'
        shared = 'True'
        args = ['--servicetype', service_type,
                '--config', config,
                '--tenant-id', tenant_id,
                '--description', description,
                '--service-profile', service_profile_id,
                '--shared', shared,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   service_type=service_type, config=config,
                                   tenant_id=tenant_id,
                                   description=description,
                                   service_profile_id=service_profile_id,
                                   shared=True)

    def test_list_servicechain_nodes(self):
        """service-chain-node-list."""
        resources = 'servicechain_nodes'
        cmd = servicechain.ListServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources(resources, cmd, True)

    def test_list_servicechain_nodes_pagination(self):
        """service-chain-node-list."""
        resources = 'servicechain_nodes'
        cmd = servicechain.ListServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_servicechain_nodes_sort(self):
        """service-chain-node-list --sort-key name --sort-key id --sort-key asc
        --sort-key desc
        """
        resources = 'servicechain_nodes'
        cmd = servicechain.ListServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_servicechain_nodes_limit(self):
        """service-chain-node-list -P."""
        resources = 'servicechain_nodes'
        cmd = servicechain.ListServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_servicechain_node_id(self):
        """service-chain-node-show test_id."""
        resource = 'servicechain_node'
        cmd = servicechain.ShowServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_servicechain_node_id_name(self):
        """service-chain-node-show."""
        resource = 'servicechain_node'
        cmd = servicechain.ShowServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_servicechain_node(self):
        """service-chain-node-update  myid --name myname --tags a b."""
        resource = 'servicechain_node'
        cmd = servicechain.UpdateServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                  None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_servicechain_node_with_all_params(self):
        resource = 'servicechain_node'
        cmd = servicechain.UpdateServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                  None)
        body = {
            'name': 'new_name',
            'description': 'new_description',
            'service_profile_id': 'new_service_profile_id',
            'shared': True,
        }
        args = ['myid', '--name', 'new_name',
                '--description', 'new_description',
                '--service-profile', 'new_service_profile_id',
                '--shared', 'True']
        self._test_update_resource(resource, cmd, 'myid', args, body)

    # REVISIT(rkukura): Not sure why the following two methods are
    # needed, since allow_put for both the service_type and config
    # attributes is False.

    def test_update_servicechain_node_with_servicetype(self):
        resource = 'servicechain_node'
        cmd = servicechain.UpdateServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                  None)
        body = {
            'service_type': 'service_type1'
        }
        args = ['myid', '--servicetype', 'service_type1']
        self._test_update_resource(resource, cmd, 'myid', args, body)

    def test_update_servicechain_node_with_type_and_config(self):
        resource = 'servicechain_node'
        cmd = servicechain.UpdateServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                  None)
        body = {
            'name': 'newname',
            'service_type': 'service_type1',
            'config': 'config1',
        }
        args = ['myid', '--name', 'newname',
                '--servicetype', 'service_type1',
                '--config', 'config1']
        self._test_update_resource(resource, cmd, 'myid', args, body)

    def test_delete_servicechain_node(self):
        """service-chain-node-delete my-id."""
        resource = 'servicechain_node'
        cmd = servicechain.DeleteServiceChainNode(test_cli20.MyApp(sys.stdout),
                                                  None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
