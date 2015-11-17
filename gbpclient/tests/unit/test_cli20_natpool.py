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


class CLITestV20NatPoolJSON(test_cli20.CLITestV20Base):

    LOG = logging.getLogger(__name__)

    def setUp(self):
        super(CLITestV20NatPoolJSON, self).setUp()

    def test_create_nat_pool_with_mandatory_params(self):
        """nat-pool-create with all mandatory params."""
        resource = 'nat_pool'
        cmd = gbp.CreateNatPool(test_cli20.MyApp(sys.stdout), None)
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

    def test_create_nat_pool_with_all_params(self):
        """nat-pool-create with all params."""
        resource = 'nat_pool'
        cmd = gbp.CreateNatPool(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        tenant_id = 'mytenant'
        description = 'My Nat Pool'
        my_id = 'someid'
        ip_version = '4'
        ip_pool = '192.168.0.0/24'
        external_segment_id = "segmentid"
        shared = 'true'
        args = ['--tenant-id', tenant_id,
                '--description', description,
                '--ip-version', ip_version,
                '--ip-pool', ip_pool,
                '--external-segment', external_segment_id,
                '--shared', shared,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id,
                                   description=description,
                                   ip_version=4,
                                   ip_pool=ip_pool,
                                   external_segment_id=external_segment_id,
                                   shared=shared)

    def test_list_nat_pools(self):
        """nat-pool-list."""
        resource = 'nat_pools'
        cmd = gbp.ListNatPool(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resource, cmd, True)

    def test_show_nat_pool_name(self):
        """nat-pool-show."""
        resource = 'nat_pool'
        cmd = gbp.ShowNatPool(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_update_nat_pool(self):
        "nat-pool-update myid --name myname --tags a b."
        resource = 'nat_pool'
        cmd = gbp.UpdateNatPool(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_nat_pool_with_all_params(self):
        resource = 'nat_pool'
        cmd = gbp.UpdateNatPool(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        description = 'My Nat Pool'
        my_id = 'someid'
        external_segment_id = "segmentid"
        shared = 'true'
        args = ['--name', name,
                '--description', description,
                '--external-segment', external_segment_id,
                '--shared', shared,
                my_id]
        params = {
            'name': name,
            'description': description,
            'external_segment_id': external_segment_id,
            'shared': shared
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_delete_nat_pool_name(self):
        """nat-pool-delete."""
        resource = 'nat_pool'
        cmd = gbp.DeleteNatPool(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
