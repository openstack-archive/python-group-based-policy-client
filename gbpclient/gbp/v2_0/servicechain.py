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

import json
import logging
import os
import string

from heatclient.common import template_utils

from neutronclient.common import exceptions as exc
from neutronclient.i18n import _
from neutronclient.neutron import v2_0 as neutronV20


class ListServiceChainInstance(neutronV20.ListCommand):
    """List service chain instances that belong to a given tenant."""

    resource = 'servicechain_instance'
    log = logging.getLogger(__name__ + '.ListServiceChainInstance')
    _formatters = {}
    list_columns = ['id', 'name', 'description', 'servicechain_spec', 'port']
    pagination_support = True
    sorting_support = True


class ShowServiceChainInstance(neutronV20.ShowCommand):
    """Show information of a given service chain instance."""

    resource = 'servicechain_instance'
    log = logging.getLogger(__name__ + '.ShowServiceChainInstance')


class CreateServiceChainInstance(neutronV20.CreateCommand):
    """Create a service chain instance."""

    resource = 'servicechain_instance'
    log = logging.getLogger(__name__ + '.CreateServiceChainInstance')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            help=_('Name for the Service Chain Instance.'))
        parser.add_argument(
            '--description',
            help=_('Description of the Service Chain Instance.'))
        parser.add_argument(
            '--service-chain-spec', dest='servicechain_spec',
            help=_('Service Chain Spec ID or the Service Chain Spec name'))
        parser.add_argument(
            '--provider-ptg', dest='provider_ptg',
            help=_('Destination Policy Target Group ID of the Provider.'))
        parser.add_argument(
            '--consumer-ptg', dest='consumer_ptg',
            help=_('Source Policy Target Group ID of the Consumer.'))
        parser.add_argument(
            '--param-values', dest='param_values',
            help=_('Name,Value pairs of Service Configuration Parameters for '
                   'Service Chain Node.'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        if parsed_args.servicechain_spec:
            body[self.resource]['servicechain_spec'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'servicechain_spec',
                    parsed_args.servicechain_spec)
        if parsed_args.provider_ptg:
            body[self.resource]['provider_ptg'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_target_group',
                    parsed_args.provider_ptg)
        if parsed_args.consumer_ptg:
            body[self.resource]['consumer_ptg'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_target_group',
                    parsed_args.consumer_ptg)
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'servicechain_spec', 'provider_ptg',
                                'consumer_ptg', 'param_values'])
        return body


class UpdateServiceChainInstance(neutronV20.UpdateCommand):
    """Update a given service chain instance."""

    resource = 'servicechain_instance'
    log = logging.getLogger(__name__ + '.UpdateServiceChainInstance')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--service-chain-spec', dest='servicechain_spec',
            help=_('Service Chain Spec ID or the Service Chain Spec name'))
        parser.add_argument(
            '--provider-ptg', dest='provider_ptg',
            help=_('Destination Policy Target Group ID of the Provider.'))
        parser.add_argument(
            '--consumer-ptg', dest='consumer_ptg',
            help=_('Source Policy Target Group ID of the Consumer.'))
        parser.add_argument(
            '--param-values', dest='param_values',
            help=_('Name,Value pairs of Service Configuration Parameters for '
                   'Service Chain Node.'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        if parsed_args.servicechain_spec:
            body[self.resource]['servicechain_spec'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'servicechain_spec',
                    parsed_args.servicechain_spec)
        if parsed_args.provider_ptg:
            body[self.resource]['provider_ptg'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_target_group',
                    parsed_args.provider_ptg)
        if parsed_args.consumer_ptg:
            body[self.resource]['consumer_ptg'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_target_group',
                    parsed_args.consumer_ptg)
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description',
                                'servicechain_spec', 'provider_ptg',
                                'consumer_ptg', 'param_values'])
        return body


class DeleteServiceChainInstance(neutronV20.DeleteCommand):
    """Delete a given service chain instance."""

    resource = 'servicechain_instance'
    log = logging.getLogger(__name__ + '.DeleteServiceChainInstance')


class ListServiceProfile(neutronV20.ListCommand):
    """List service profiles that belong to a given tenant."""

    resource = 'service_profile'
    log = logging.getLogger(__name__ + '.ListServiceProfile')
    _formatters = {}
    list_columns = ['id', 'name', 'description', 'service_type']
    pagination_support = True
    sorting_support = True


class ShowServiceProfile(neutronV20.ShowCommand):
    """Show information of a given service profile."""

    resource = 'service_profile'
    log = logging.getLogger(__name__ + '.ShowServiceProfile')


class CreateServiceProfile(neutronV20.CreateCommand):
    """Create a service profile."""

    resource = 'service_profile'
    log = logging.getLogger(__name__ + '.CreateServiceProfile')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            help=_('Name for the Service Profile.'))
        parser.add_argument(
            '--description',
            help=_('Description of the Service Profile.'))
        parser.add_argument(
            '--shared', type=bool,
            help=_('Shared flag'))
        parser.add_argument(
            '--vendor',
            help=_('Vendor providing the service node'))
        parser.add_argument(
            '--insertion-mode',
            help=_('Insertion mode of the service'))
        parser.add_argument(
            '--servicetype', dest='service_type',
            help=_('Type of the service'))
        parser.add_argument(
            '--service-flavor',
            help=_('Flavor of the service'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'tenant_id', 'shared',
                                'vendor', 'insertion_mode', 'service_type',
                                'service_flavor'])
        return body


class UpdateServiceProfile(neutronV20.UpdateCommand):
    """Update a given service profile."""

    resource = 'service_profile'
    log = logging.getLogger(__name__ + '.UpdateServiceProfile')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Name for the Service Profile.'))
        parser.add_argument(
            '--description',
            help=_('Description of the Service Profile.'))
        parser.add_argument(
            '--shared', type=bool,
            help=_('Shared flag'))
        parser.add_argument(
            '--vendor',
            help=_('Vendor providing the service node'))
        parser.add_argument(
            '--insertion-mode',
            help=_('Insertion mode of the service'))
        parser.add_argument(
            '--servicetype', dest='service_type',
            help=_('Type of the service'))
        parser.add_argument(
            '--service-flavor',
            help=_('Flavor of the service'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'shared', 'vendor',
                                'insertion_mode', 'service_type',
                                'service_flavor'])
        return body


class DeleteServiceProfile(neutronV20.DeleteCommand):
    """Delete a given service profile."""

    resource = 'service_profile'
    log = logging.getLogger(__name__ + '.DeleteServiceProfile')


class ListServiceChainNode(neutronV20.ListCommand):
    """List service chain nodes that belong to a given tenant."""

    resource = 'servicechain_node'
    log = logging.getLogger(__name__ + '.ListServiceChainNode')
    _formatters = {}
    list_columns = ['id', 'name', 'description', 'service_type']
    pagination_support = True
    sorting_support = True


class ShowServiceChainNode(neutronV20.ShowCommand):
    """Show information of a given service chain node."""

    resource = 'servicechain_node'
    log = logging.getLogger(__name__ + '.ShowServiceChainNode')


class CreateServiceChainNode(neutronV20.CreateCommand):
    """Create a service chain node."""

    resource = 'servicechain_node'
    log = logging.getLogger(__name__ + '.CreateServiceChainNode')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            help=_('Name for the Service Chain Node.'))
        parser.add_argument(
            '--description',
            help=_('Description of the Service Chain Node.'))
        parser.add_argument(
            '--servicetype', dest='service_type',
            help=_('Service type ID or the Service Type name'))
        parser.add_argument(
            '--service-profile',
            help=_('Service Profile name or UUID'))
        parser.add_argument(
            '--config',
            help=_('Service Configuration for the Service Chain Node.'))
        parser.add_argument(
            '--shared', type=bool,
            help=_('Shared flag'))
        parser.add_argument(
            '--template-file',
            help=_('Service Configuration Template for the Service Chain '
                   'Node.'))
        parser.add_argument(
            '--param-names', dest='param_names',
            help=_('List of Configuration Parameter Names for Service '
                   'Chain Node.'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        if parsed_args.service_profile:
            body[self.resource]['service_profile_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'service_profile',
                    parsed_args.service_profile)
        if parsed_args.template_file:
            if os.path.isfile(parsed_args.template_file):
                tpl_files, template = template_utils.get_template_contents(
                    parsed_args.template_file)
                parsed_args.config = json.dumps(template)
            else:
                raise exc.NeutronClientException("File %s does not exist. "
                                                 "Please check the path"
                                                 % parsed_args.template_file)
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'service_type', 'config', 'shared',
                                'tenant_id', 'param_names', 'description'])
        return body


class UpdateServiceChainNode(neutronV20.UpdateCommand):
    """Update a given service chain node."""

    resource = 'servicechain_node'
    log = logging.getLogger(__name__ + '.UpdateServiceChainNode')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--servicetype', dest='service_type',
            help=_('Service type ID or the Service Type name'))
        parser.add_argument(
            '--service-profile',
            help=_('Service Profile name or UUID'))
        parser.add_argument(
            '--config',
            help=_('Service Configuration for the Service Chain Node.'))
        parser.add_argument(
            '--shared', type=bool,
            help=_('Shared flag'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        if parsed_args.service_profile:
            body[self.resource]['service_profile_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'service_profile',
                    parsed_args.service_profile)
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'service_type', 'config', 'shared',
                                'description'])
        return body


class DeleteServiceChainNode(neutronV20.DeleteCommand):
    """Delete a given service chain node."""

    resource = 'servicechain_node'
    log = logging.getLogger(__name__ + '.DeleteServiceChainNode')


class ListServiceChainSpec(neutronV20.ListCommand):
    """List service chain specs that belong to a given tenant."""

    resource = 'servicechain_spec'
    log = logging.getLogger(__name__ + '.ListServiceChainSpec')
    _formatters = {}
    list_columns = ['id', 'name', 'description', 'nodes']
    pagination_support = True
    sorting_support = True


class ShowServiceChainSpec(neutronV20.ShowCommand):
    """Show information of a given service chain spec."""

    resource = 'servicechain_spec'
    log = logging.getLogger(__name__ + '.ShowServiceChainSpec')


class CreateServiceChainSpec(neutronV20.CreateCommand):
    """Create a service chain spec."""

    resource = 'servicechain_spec'
    log = logging.getLogger(__name__ + '.CreateServiceChainSpec')

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            help=_('Name for the Service Chain Spec.'))
        parser.add_argument(
            '--description',
            help=_('Description of the Service Chain Specification.'))
        parser.add_argument(
            '--nodes', metavar='NODES', type=string.split,
            help=_('Service Chain Node ID or name of the Service Chain Node'))
        parser.add_argument(
            '--shared', type=bool,
            help=_('Shared flag'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.nodes:
            body[self.resource]['nodes'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'servicechain_node',
                    elem) for elem in parsed_args.nodes]

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description', 'shared'])
        return body


class UpdateServiceChainSpec(neutronV20.UpdateCommand):
    """Update a given service chain spec."""

    resource = 'servicechain_spec'
    log = logging.getLogger(__name__ + '.UpdateServiceChainSpec')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--nodes', type=string.split,
            help=_('List of Service Chain Node IDs or names of the Service '
                   'Chain Nodes'))
        parser.add_argument(
            '--shared', type=bool,
            help=_('Shared flag'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        if parsed_args.nodes:
            body[self.resource]['nodes'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'servicechain_node',
                    elem) for elem in parsed_args.nodes]
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'shared'])
        return body


class DeleteServiceChainSpec(neutronV20.DeleteCommand):
    """Delete a given service chain spec."""

    resource = 'servicechain_spec'
    log = logging.getLogger(__name__ + '.DeleteServiceChainSpec')
