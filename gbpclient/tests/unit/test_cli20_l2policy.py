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


class CLITestV20L2PolicyJSON(test_cli20.CLITestV20Base):

    LOG = logging.getLogger(__name__)

    def setUp(self):
        super(CLITestV20L2PolicyJSON, self).setUp()

    def test_create_l2_policy_with_mandatory_params(self):
        resource = 'l2_policy'
        cmd = gbp.CreateL2Policy(test_cli20.MyApp(sys.stdout), None)
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

    def test_create_l2_policy_with_all_params(self):
        """l2-policy-create with all params."""
        resource = 'l2_policy'
        cmd = gbp.CreateL2Policy(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        tenant_id = 'my-tenant'
        name = 'my-name'
        description = 'l2p description'
        l3_policy_id = 'l3p'
        inject_default_route = 'false'
        shared = 'true'
        args = [name,
                '--tenant-id', tenant_id,
                '--description', description,
                '--l3-policy-id', l3_policy_id,
                '--inject-default-route', inject_default_route,
                '--shared', shared]
        position_names = ['name', 'description', 'l3_policy_id']
        position_values = [name, description, l3_policy_id]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id, shared=shared,
                                   inject_default_route=inject_default_route)

    def test_list_l2_policies(self):
        resource = 'l2_policies'
        cmd = gbp.ListL2Policy(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resource, cmd, True)

    def test_show_l2_policy(self):
        resource = 'l2_policy'
        cmd = gbp.ShowL2Policy(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_update_l2_policy(self):
        resource = 'l2_policy'
        cmd = gbp.UpdateL2Policy(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_l2_policy_with_all_params(self):
        """l2-policy-update."""
        resource = 'l2_policy'
        cmd = gbp.UpdateL2Policy(test_cli20.MyApp(sys.stdout), None)
        my_id = 'someid'
        name = 'l2policy'
        description = 'l2policy description'
        l3_policy_id = 'l3p'
        inject_default_route = 'false'
        shared = 'true'
        args = [my_id,
                '--name', name,
                '--description', description,
                '--l3-policy-id', l3_policy_id,
                '--inject-default-route', inject_default_route,
                '--shared', shared]
        params = {
            'name': name,
            'description': description,
            'l3_policy_id': l3_policy_id,
            'inject_default_route': inject_default_route,
            'shared': shared
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_delete_l2_policy_name(self):
        resource = 'l2_policy'
        cmd = gbp.DeleteL2Policy(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
