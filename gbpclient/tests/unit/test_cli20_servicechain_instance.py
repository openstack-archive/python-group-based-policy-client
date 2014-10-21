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

from gbpclient.gbp.v2_0 import servicechain as sc
from gbpclient.tests.unit import test_cli20


class CLITestV20ServiceChainInstanceJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20ServiceChainInstanceJSON, self).setUp()

    def test_create_servicechain_instance_with_mandatory_params(self):
        """service-chain-instance-create with all mandatory params."""
        resource = 'servicechain_instance'
        cmd = sc.CreateServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        name = 'my-name'
        tenant_id = 'my-tenant'
        my_id = 'my-id'
        args = ['--tenant-id', tenant_id, name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id)

    def test_create_servicechain_instance_with_all_params(self):
        """service-chain-instance-create with all params."""
        resource = 'servicechain_instance'
        cmd = sc.CreateServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        name = 'my-name'
        servicechain_spec_id = 'service-chain-spec-id'
        tenant_id = 'my-tenant'
        description = 'My Service Chain Instance'
        my_id = 'my-id'
        config_params = 'config'
        args = ['--service-chain-spec', servicechain_spec_id,
                '--tenant-id', tenant_id,
                '--param-values', config_params,
                '--description', description,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   servicechain_spec=servicechain_spec_id,
                                   tenant_id=tenant_id,
                                   param_values=config_params,
                                   description=description)

    def test_list_servicechain_instances(self):
        """service-chain-instance-list."""
        resources = 'servicechain_instances'
        cmd = sc.ListServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_servicechain_instances_pagination(self):
        """service-chain-instance-list."""
        resources = 'servicechain_instances'
        cmd = sc.ListServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_servicechain_instances_sort(self):
        """service-chain-instance-list --sort-key name --sort-key id
        --sort-key asc --sort-key desc
        """
        resources = 'servicechain_instances'
        cmd = sc.ListServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_servicechain_instances_limit(self):
        """service-chain-instance-list -P."""
        resources = 'servicechain_instances'
        cmd = sc.ListServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_servicechain_instance_id(self):
        """service-chain-instance-show test_id."""
        resource = 'servicechain_instance'
        cmd = sc.ShowServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_servicechain_instance_id_name(self):
        """service-chain-instance-show."""
        resource = 'servicechain_instance'
        cmd = sc.ShowServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_servicechain_instance(self):
        """service-chain-instance-update  myid --name myname --tags a b."""
        resource = 'servicechain_instance'
        cmd = sc.UpdateServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_servicechain_instance_with_chainspec(self):
        resource = 'servicechain_instance'
        cmd = sc.UpdateServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        body = {
            'servicechain_spec': 'my-spec-id'
        }
        args = ['myid', '--service-chain-spec', 'my-spec-id']
        self._test_update_resource(resource, cmd, 'myid', args, body)

    def test_update_servicechain_instance_with_chainspec_and_port(self):
        resource = 'servicechain_instance'
        cmd = sc.UpdateServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        body = {
            'name': 'newname',
            'servicechain_spec': 'my-spec-id',
            'port': 'my-port-id'
        }
        args = ['myid', '--name', 'newname',
                '--service-chain-spec', 'my-spec-id',
                '--port', 'my-port-id']
        self._test_update_resource(resource, cmd, 'myid', args, body)

    def test_delete_servicechain_instance(self):
        """service-chain-instance-delete my-id."""
        resource = 'servicechain_instance'
        cmd = sc.DeleteServiceChainInstance(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
