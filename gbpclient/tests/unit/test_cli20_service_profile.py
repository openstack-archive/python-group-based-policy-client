# Copyright 2015 OpenStack Foundation.
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


class CLITestV20ServiceProfileJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20ServiceProfileJSON, self).setUp()

    def test_create_service_profile_with_mandatory_params(self):
        """service-profile-create with all mandatory params."""
        resource = 'service_profile'
        cmd = servicechain.CreateServiceProfile(test_cli20.MyApp(sys.stdout),
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

    def test_create_service_profile_with_all_params(self):
        """service-profile-create with all params."""
        resource = 'service_profile'
        cmd = servicechain.CreateServiceProfile(test_cli20.MyApp(sys.stdout),
                                                None)
        name = 'my-name'
        description = 'My Service Profile'
        tenant_id = 'my-tenant'
        shared = 'true'
        vendor = 'vendor'
        insertion_mode = 'some mode'
        service_type = 'servicetype1'
        service_flavor = 'cherry-garcia'
        my_id = 'my-id'
        args = ['--description', description,
                '--tenant-id', tenant_id,
                '--shared', shared,
                '--vendor', vendor,
                '--insertion-mode', insertion_mode,
                '--servicetype', service_type,
                '--service-flavor', service_flavor,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   description=description,
                                   tenant_id=tenant_id,
                                   shared=shared,
                                   vendor=vendor,
                                   insertion_mode=insertion_mode,
                                   service_type=service_type,
                                   service_flavor=service_flavor)

    def test_list_service_profiles(self):
        """service-profile-list."""
        resources = 'service_profiles'
        cmd = servicechain.ListServiceProfile(test_cli20.MyApp(sys.stdout),
                                              None)
        self._test_list_resources(resources, cmd, True)

    def test_list_service_profiles_pagination(self):
        """service-profile-list."""
        resources = 'service_profiles'
        cmd = servicechain.ListServiceProfile(test_cli20.MyApp(sys.stdout),
                                              None)
        self._test_list_resources_with_pagination(resources, cmd)

    def test_list_service_profiles_sort(self):
        """service-profile-list --sort-key name --sort-key id --sort-key asc
        --sort-key desc
        """
        resources = 'service_profiles'
        cmd = servicechain.ListServiceProfile(test_cli20.MyApp(sys.stdout),
                                              None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_service_profiles_limit(self):
        """service-profile-list -P."""
        resources = 'service_profiles'
        cmd = servicechain.ListServiceProfile(test_cli20.MyApp(sys.stdout),
                                              None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_service_profile_id(self):
        """service-profile-show test_id."""
        resource = 'service_profile'
        cmd = servicechain.ShowServiceProfile(test_cli20.MyApp(sys.stdout),
                                              None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_service_profile_id_name(self):
        """service-profile-show."""
        resource = 'service_profile'
        cmd = servicechain.ShowServiceProfile(test_cli20.MyApp(sys.stdout),
                                              None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_service_profile(self):
        """service-profile-update  myid --name myname --tags a b."""
        resource = 'service_profile'
        cmd = servicechain.UpdateServiceProfile(test_cli20.MyApp(sys.stdout),
                                                None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_service_profile_with_all_params(self):
        resource = 'service_profile'
        cmd = servicechain.UpdateServiceProfile(test_cli20.MyApp(sys.stdout),
                                                None)
        name = 'new-name'
        description = 'My Updated Service Profile'
        shared = 'true'
        vendor = 'open-source'
        insertion_mode = 'another mode'
        service_type = 'servicetype2'
        service_flavor = 'phish-food'
        body = {
            'name': name,
            'description': description,
            'shared': shared,
            'vendor': vendor,
            'insertion_mode': insertion_mode,
            'service_type': service_type,
            'service_flavor': service_flavor}
        args = ['myid', '--name', name,
                '--description', description,
                '--shared', shared,
                '--vendor', vendor,
                '--insertion-mode', insertion_mode,
                '--servicetype', service_type,
                '--service-flavor', service_flavor]
        self._test_update_resource(resource, cmd, 'myid', args, body)

    def test_delete_service_profile(self):
        """service-profile-delete my-id."""
        resource = 'service_profile'
        cmd = servicechain.DeleteServiceProfile(test_cli20.MyApp(sys.stdout),
                                                None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
