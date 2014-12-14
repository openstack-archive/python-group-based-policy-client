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


class CLITestV20ExternalSegmentJSON(test_cli20.CLITestV20Base):

    LOG = logging.getLogger(__name__)

    def setUp(self):
        super(CLITestV20ExternalSegmentJSON, self).setUp()

    def test_create_external_segment_with_mandatory_params(self):
        """external-segment-create with all mandatory params."""
        resource = 'external_segment'
        cmd = gbp.CreateExternalSegment(test_cli20.MyApp(sys.stdout), None)
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

    def test_create_external_segment_with_all_params(self):
        """external-segment-create with all params."""
        resource = 'external_segment'
        cmd = gbp.CreateExternalSegment(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        tenant_id = 'mytenant'
        description = 'My External Segment'
        my_id = 'someid'
        ip_version = '4'
        cidr = '192.168.0.0/24'
        external_route = 'destination=172.16.1.0/24,nexthop=192.168.0.10'
        expected_external_routes = [{'destination': '172.16.1.0/24', 'nexthop':
                                    '192.168.0.10'}]
        port_address_translation = 'True'
        shared = 'True'
        args = ['--tenant-id', tenant_id,
                '--description', description,
                '--ip-version', ip_version,
                '--cidr', cidr,
                '--external-route', external_route,
                '--port-address-translation', port_address_translation,
                '--shared', shared,
                name]
        position_names = ['name', ]
        position_values = [name, ]
        self._test_create_resource(resource, cmd, name, my_id, args,
                                   position_names, position_values,
                                   tenant_id=tenant_id,
                                   description=description,
                                   ip_version=4,
                                   cidr=cidr,
                                   external_routes=expected_external_routes,
                                   port_address_translation=True,
                                   shared=True)

    def test_list_external_segments(self):
        """external-segment-list."""
        resource = 'external_segments'
        cmd = gbp.ListExternalSegment(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resource, cmd, True)

    def test_show_external_segment_name(self):
        """external-segment-show."""
        resource = 'external_segment'
        cmd = gbp.ShowExternalSegment(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_update_external_segment(self):
        "external-segment-update myid --name myname --tags a b."
        resource = 'external_segment'
        cmd = gbp.UpdateExternalSegment(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--tags', 'a', 'b'],
                                   {'name': 'myname', 'tags': ['a', 'b'], })

    def test_update_external_segment_with_all_params(self):
        resource = 'external_segment'
        cmd = gbp.UpdateExternalSegment(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        description = 'My External Segment'
        my_id = 'someid'
        ip_version = '4'
        cidr = '192.168.0.0/24'
        external_route = 'destination=172.16.1.0/24,nexthop=192.168.0.10'
        expected_external_routes = [{'destination': '172.16.1.0/24', 'nexthop':
                                    '192.168.0.10'}]
        port_address_translation = 'True'
        shared = 'True'
        args = ['--name', name,
                '--description', description,
                '--ip-version', ip_version,
                '--cidr', cidr,
                '--external-route', external_route,
                '--port-address-translation', port_address_translation,
                '--shared', shared,
                my_id]
        params = {
            'name': name,
            'description': description,
            'ip_version': 4,
            'cidr': cidr,
            'external_routes': expected_external_routes,
            'port_address_translation': True,
            'shared': True
        }
        self._test_update_resource(resource, cmd, my_id, args, params)

    def test_delete_external_segment_name(self):
        """external-segment-delete."""
        resource = 'external_segment'
        cmd = gbp.DeleteExternalSegment(test_cli20.MyApp(sys.stdout), None)
        my_id = 'my-id'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
