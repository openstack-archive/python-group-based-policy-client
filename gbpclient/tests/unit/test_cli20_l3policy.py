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


class CLITestV20L3PolicyJSON(test_cli20.CLITestV20Base):

    LOG = logging.getLogger(__name__)

    def setUp(self):
        super(CLITestV20L3PolicyJSON, self).setUp()

    def test_create_l3_policy_with_mandatory_params(self):
        resource = 'l3_policy'
        cmd = gbp.CreateL3Policy(test_cli20.MyApp(sys.stdout), None)
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

    def test_create_l3_policy_with_all_params(self):
        """l3-policy-create with all params."""
        resource = 'l3_policy'
        cmd = gbp.CreateL3Policy(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        tenant_id = 'mytenant'
        description = 'My L3 Policy'
        my_id = 'someid'
        ip_version = '4'
        ip_pool = '172.16.0.0/12'
        subnet_prefix_length = '24'
        external_segment = 'seg_uuid1=1.1.1.0:2.2.2.0'
        expected_external_segments = {'seg_uuid1': ['1.1.1.0', '2.2.2.0']}
        shared = 'True'
        args = ['--tenant-id', tenant_id,
                '--description', description,
                '--ip-version', ip_version,
                '--ip-pool', ip_pool,
                '--subnet-prefix-length', subnet_prefix_length,
                '--external-segment', external_segment,
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
                                   subnet_prefix_length=24,
                                   external_segments=
                                   expected_external_segments, shared=True)

    def test_list_l3_policies(self):
        resource = 'l3_policies'
        cmd = gbp.ListL3Policy(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resource, cmd, True)

    def test_show_l3_policy(self):
        resource = 'l3_policy'
        cmd = gbp.ShowL3Policy(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_update_l3_policy(self):
        resource = 'l3_policy'
        cmd = gbp.UpdateL3Policy(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_l3_policy_with_all_params(self):
        resource = 'l3_policy'
        cmd = gbp.UpdateL3Policy(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        description = 'My L3 Policy'
        my_id = 'someid'
        ip_version = '4'
        ip_pool = '172.16.0.0/12'
        subnet_prefix_length = '24'
        external_segment = 'seg_uuid1=1.1.1.0:2.2.2.0'
        expected_external_segments = {'seg_uuid1': ['1.1.1.0', '2.2.2.0']}
        shared = 'True'
        args = ['--name', name,
                '--description', description,
                '--ip-version', ip_version,
                '--ip-pool', ip_pool,
                '--subnet-prefix-length', subnet_prefix_length,
                '--external-segment', external_segment,
                '--shared', shared,
                my_id]
        params = {
            'name': name,
            'description': description,
            'ip_version': 4,
            'ip_pool': ip_pool,
            'subnet_prefix_length': 24,
            'external_segments': expected_external_segments,
            'shared': True
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_update_l3_policy_unset_external_segment(self):
        resource = 'l3_policy'
        cmd = gbp.UpdateL3Policy(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        description = 'My L3 Policy'
        my_id = 'someid'
        ip_version = '4'
        ip_pool = '172.16.0.0/12'
        subnet_prefix_length = '24'
        external_segment = ''
        expected_external_segments = {}
        args = ['--name', name,
                '--description', description,
                '--ip-version', ip_version,
                '--ip-pool', ip_pool,
                '--subnet-prefix-length', subnet_prefix_length,
                '--external-segment', external_segment,
                my_id]
        params = {
            'name': name,
            'description': description,
            'ip_version': 4,
            'ip_pool': ip_pool,
            'subnet_prefix_length': 24,
            'external_segments': expected_external_segments,
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_delete_l3_policy_name(self):
        resource = 'l3_policy'
        cmd = gbp.DeleteL3Policy(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
