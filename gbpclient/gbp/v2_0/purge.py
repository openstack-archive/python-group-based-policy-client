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

import re
import sys

from neutronclient.common import exceptions as nexc
from neutronclient.neutron.v2_0 import purge as n_purge

AUTO_PTG_REGEX = 'auto[0-9a-f]{32}\Z'


class Purge(n_purge.Purge):
    """Delete all resources that belong to a given tenant."""

    def _pluralize(self, string):
        if re.search('_policy$', string):
            return re.sub('_policy$', '_policies', string)
        return string + 's'

    def _get_resources(self, neutron_client, resource_types, tenant_id):
        resources = super(Purge, self)._get_resources(neutron_client,
                                                      resource_types,
                                                      tenant_id)
        # exclude auto_ptg as it was created by implicit workflow
        if 'policy_target_group' in resource_types:
            index = resource_types.index('policy_target_group')
            for resource in list(resources[index]):
                if re.match(AUTO_PTG_REGEX, resource['id']):
                    resources[index].remove(resource)
                    self.total_resources -= 1
        return resources

    def _purge_resources(self, neutron_client, resource_types,
                         tenant_resources):
        deleted = {}
        failed = {}
        failures = False
        for index, resources in enumerate(tenant_resources):
            resource_type = resource_types[index]
            failed[resource_type] = 0
            deleted[resource_type] = 0
            for resource in resources:
                try:
                    self._delete_resource(neutron_client, resource_type,
                                          resource)
                    deleted[resource_type] += 1
                    self.deleted_resources += 1
                except nexc.NotFound:
                    # this is for l2p/l3p created under the
                    # implicit workflow.
                    deleted[resource_type] += 1
                    self.deleted_resources += 1
                except Exception:
                    failures = True
                    failed[resource_type] += 1
                    self.total_resources -= 1
                percent_complete = 100
                if self.total_resources > 0:
                    percent_complete = (self.deleted_resources /
                                        float(self.total_resources)) * 100
                sys.stdout.write("\rPurging resources: %d%% complete." %
                                 percent_complete)
                sys.stdout.flush()
        return (deleted, failed, failures)

    def take_action(self, parsed_args):
        neutron_client = self.get_client()

        self.any_failures = False

        # A list of the types of resources supported in the order in which
        # they should be deleted.
        resource_types = ['policy_target', 'policy_target_group', 'l2_policy',
                          'l3_policy', 'external_policy', 'nat_pool',
                          'external_segment', 'policy_rule_set',
                          'policy_rule', 'policy_classifier',
                          'policy_action', 'network_service_policy',
                          'servicechain_instance', 'servicechain_spec',
                          'servicechain_node', 'service_profile',
                          'application_policy_group']
        deleted = {}
        failed = {}
        self.total_resources = 0
        self.deleted_resources = 0
        resources = self._get_resources(neutron_client, resource_types,
                                        parsed_args.tenant)
        deleted, failed, failures = self._purge_resources(neutron_client,
                                                          resource_types,
                                                          resources)
        print('\n%s' % self._build_message(deleted, failed, failures))

        # clean up Neutron resources also
        super(Purge, self).take_action(parsed_args)


class PurgeAPI(Purge):
    def __init__(self, app, app_args, gbp_client):
        self.gbp_client = gbp_client
        super(PurgeAPI, self).__init__(app, app_args)

    def get_client(self):
        return self.gbp_client
