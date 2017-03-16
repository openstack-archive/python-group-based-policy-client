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

import argparse
import logging

from neutronclient.common import utils as n_utils
from neutronclient.i18n import _
from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.v2_0 import client as neutron_client
from oslo_serialization import jsonutils

from gbpclient.common import utils

neutron_client.UUID_PATTERN = neutron_client.UUID_PATTERN + (
    '|auto' + neutron_client.HEX_ELEM + '{32}')


def _format_fixed_ips(pt):
    try:
        return '\n'.join([jsonutils.dumps(ip) for ip in pt['fixed_ips']])
    except (TypeError, KeyError):
        return ''


def _format_network_service_params(net_svc_policy):
    try:
        return '\n'.join([jsonutils.dumps(param) for param in
                          net_svc_policy['network_service_params']])
    except (TypeError, KeyError):
        return ''


def _format_host_routes(subnet):
    try:
        return '\n'.join([jsonutils.dumps(route) for route in
                          subnet['host_routes']])
    except (TypeError, KeyError):
        return ''


class ListPolicyTarget(neutronV20.ListCommand):
    """List policy_targets that belong to a given tenant."""

    resource = 'policy_target'
    log = logging.getLogger(__name__ + '.ListPolicyTarget')
    _formatters = {'fixed_ips': _format_fixed_ips, }
    list_columns = ['id', 'name', 'description', 'policy_target_group_id',
                    'port_id', 'fixed_ips']
    pagination_support = True
    sorting_support = True


class ShowPolicyTarget(neutronV20.ShowCommand):
    """Show information of a given policy_target."""

    resource = 'policy_target'
    log = logging.getLogger(__name__ + '.ShowPolicyTarget')


class CreatePolicyTarget(neutronV20.CreateCommand):
    """Create a policy_target for a given tenant."""

    resource = 'policy_target'
    log = logging.getLogger(__name__ + '.CreatePolicyTarget')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the Policy Target'))
        parser.add_argument(
            '--policy-target-group',
            help=_('Policy Target Group (required argument)'))
        parser.add_argument(
            '--fixed-ip', metavar='subnet_id=SUBNET,ip_address=IP_ADDR',
            action='append',
            type=n_utils.str2dict_type(optional_keys=['subnet_id',
                                                      'ip_address']),
            help=_('Desired IP and/or subnet for this Policy Target: '
                   'subnet_id=<nid>,ip_address=<ip>. '
                   'You can repeat this option.'))
        parser.add_argument(
            '--fixed_ip', action='append', help=argparse.SUPPRESS)
        parser.add_argument(
            '--port-id', default='',
            help=_('Neutron Port UUID'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of Policy Target to create (required argument)'))
        parser.add_argument(
            '--segmentation-labels', type=utils.str2list,
            help=_('Comma separated list of segmentation labels, each label '
                   'can be upto 255 characters. This option is currently '
                   'only available with the APIC backend.'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'segmentation_labels'])
        if parsed_args.policy_target_group:
            body[self.resource]['policy_target_group_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_target_group',
                    parsed_args.policy_target_group)

        if parsed_args.port_id:
            body[self.resource]['port_id'] = (
                parsed_args.port_id)

        if parsed_args.fixed_ip:
            body[self.resource]['fixed_ips'] = parsed_args.fixed_ip

        return body


class DeletePolicyTarget(neutronV20.DeleteCommand):
    """Delete a given Policy Target."""

    resource = 'policy_target'
    log = logging.getLogger(__name__ + '.DeletePolicyTarget')


class UpdatePolicyTarget(neutronV20.UpdateCommand):
    """Update Policy Target's information."""

    resource = 'policy_target'
    log = logging.getLogger(__name__ + '.UpdatePolicyTarget')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the Policy Target'))
        parser.add_argument(
            '--name',
            help=_('New name of the Policy Target'))
        parser.add_argument(
            '--fixed-ip', metavar='subnet_id=SUBNET,ip_address=IP_ADDR',
            action='append',
            type=n_utils.str2dict_type(optional_keys=['subnet_id',
                                                      'ip_address']),
            help=_('Desired IP and/or subnet for this Policy Target: '
                   'subnet_id=<nid>,ip_address=<ip>. '
                   'You can repeat this option.'))
        parser.add_argument(
            '--fixed_ip', action='append', help=argparse.SUPPRESS)
        parser.add_argument(
            '--segmentation-labels', type=utils.str2list,
            help=_('Comma separated list of segmentation labels, each label '
                   'can be upto 255 characters. This option is currently '
                   'only available with the APIC backend.'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'segmentation_labels'])

        if parsed_args.fixed_ip:
            body[self.resource]['fixed_ips'] = parsed_args.fixed_ip

        return body


class ListPolicyTargetGroup(neutronV20.ListCommand):
    """List Policy Target Groups that belong to a given tenant."""

    resource = 'policy_target_group'
    log = logging.getLogger(__name__ + '.ListPolicyTargetGroup')
    list_columns = ['id', 'name', 'description', 'application_policy_group_id',
                    'l2_policy_id', 'subnets']
    pagination_support = True
    sorting_support = True


class ShowPolicyTargetGroup(neutronV20.ShowCommand):
    """Show information of a given Policy Target Group."""

    resource = 'policy_target_group'
    log = logging.getLogger(__name__ + '.ShowPolicyTargetGroup')


class CreatePolicyTargetGroup(neutronV20.CreateCommand):
    """Create a Policy Target Group for a given tenant."""

    resource = 'policy_target_group'
    log = logging.getLogger(__name__ + '.CreatePolicyTargetGroup')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the Policy Target Group'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of Policy Target Group to create '
                   '(required argument)'))
        parser.add_argument(
            '--application-policy-group', metavar='APPLICATION_POLICY_GROUP',
            default='',
            help=_('Application Policy Group UUID (optional, default '
                   'is None)'))
        parser.add_argument(
            '--l2-policy', metavar='L2_POLICY',
            default='',
            help=_('L2 Policy UUID (if not specified, default is used)'))
        parser.add_argument(
            '--provided-policy-rule-sets', type=utils.str2dict,
            help=_('Comma separated list of Policy Rule Sets'))
        parser.add_argument(
            '--consumed-policy-rule-sets', type=utils.str2dict,
            help=_('Comma separated list of Policy Rule Sets'))
        parser.add_argument(
            '--network-service-policy', metavar='NETWORK_SERVICE_POLICY',
            default='',
            help=_('Network Service Policy'))
        parser.add_argument(
            '--subnets', type=utils.str2list,
            help=_('Comma separated list of Neutron Subnet UUIDs'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))
        n_utils.add_boolean_argument(
            parser, '--intra-ptg-allow', dest='intra_ptg_allow',
            help=_("Allow or disallow communication between Policy Targets of "
                   "this Policy Target Group. Default is True, i.e., all "
                   "Policy Targets can communicate with each other. This "
                   "option is only available with the APIC backend."))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.l2_policy:
            body[self.resource]['l2_policy_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'l2_policy',
                    parsed_args.l2_policy)

        if parsed_args.application_policy_group:
            body[self.resource]['application_policy_group_id'] = (
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'application_policy_group',
                    parsed_args.application_policy_group))

        if parsed_args.network_service_policy:
            body[self.resource]['network_service_policy_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'network_service_policy',
                    parsed_args.network_service_policy)

        if parsed_args.provided_policy_rule_sets:
            for key in parsed_args.provided_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.provided_policy_rule_sets[id_key] = \
                    parsed_args.provided_policy_rule_sets.pop(key)

        if parsed_args.consumed_policy_rule_sets:
            for key in parsed_args.consumed_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.consumed_policy_rule_sets[id_key] = \
                    parsed_args.consumed_policy_rule_sets.pop(key)

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'provided_policy_rule_sets', 'subnets',
                                'consumed_policy_rule_sets', 'shared',
                                'intra_ptg_allow'])

        return body


class DeletePolicyTargetGroup(neutronV20.DeleteCommand):
    """Delete a given Policy Target Group."""

    resource = 'policy_target_group'
    log = logging.getLogger(__name__ + '.DeletePolicyTargetGroup')


class UpdatePolicyTargetGroup(neutronV20.UpdateCommand):
    """Update Policy Target Group's information."""

    resource = 'policy_target_group'
    log = logging.getLogger(__name__ + '.UpdatePolicyTargetGroup')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the Policy Target Group'))
        parser.add_argument(
            '--l2-policy', metavar='L2_POLICY',
            help=_('New L2 policy'))
        parser.add_argument(
            '--application-policy-group', metavar='APPLICATION_POLICY_GROUP',
            help=_('New Application Policy Group'))
        parser.add_argument(
            '--network-service-policy', metavar='NETWORK_SERVICE_POLICY',
            help=_('New Network Service Policy'))
        parser.add_argument(
            '--provided-policy-rule-sets', type=utils.str2dict,
            help=_('New comma separated list of Policy Rule Sets '
                   '(to unset use "")'))
        parser.add_argument(
            '--consumed-policy-rule-sets', type=utils.str2dict,
            help=_('New comma separated list of Policy Rule Sets '
                   '(to unset use "")'))
        parser.add_argument(
            '--subnets', type=utils.str2list,
            help=_('New comma separated list of Neutron Subnet UUIDs '
                   '(to unset use "")'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))
        n_utils.add_boolean_argument(
            parser, '--intra-ptg-allow', dest='intra_ptg_allow',
            help=_("Allow or disallow communication between Policy Targets of "
                   "this Policy Target Group. Default is True, i.e., all "
                   "Policy Targets can communicate with each other. This "
                   "option is only available with the APIC backend."))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.l2_policy:
            body[self.resource]['l2_policy_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'l2_policy',
                    parsed_args.l2_policy)

        if parsed_args.application_policy_group == '':
            body[self.resource]['application_policy_group_id'] = None
        elif parsed_args.application_policy_group:
            body[self.resource]['application_policy_group_id'] = (
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'application_policy_group',
                    parsed_args.application_policy_group))

        if parsed_args.network_service_policy == '':
            body[self.resource]['network_service_policy_id'] = None
        elif parsed_args.network_service_policy:
            body[self.resource]['network_service_policy_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'network_service_policy',
                    parsed_args.network_service_policy)

        if parsed_args.provided_policy_rule_sets:
            for key in parsed_args.provided_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.provided_policy_rule_sets[id_key] = \
                    parsed_args.provided_policy_rule_sets.pop(key)

        if parsed_args.consumed_policy_rule_sets:
            for key in parsed_args.consumed_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.consumed_policy_rule_sets[id_key] = \
                    parsed_args.consumed_policy_rule_sets.pop(key)

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'provided_policy_rule_sets', 'subnets',
                                'consumed_policy_rule_sets', 'shared',
                                'intra_ptg_allow'])

        return body


class ListL2Policy(neutronV20.ListCommand):
    """List L2 Policies that belong to a given tenant."""

    resource = 'l2_policy'
    log = logging.getLogger(__name__ + '.ListL2Policy')
    _formatters = {}
    list_columns = ['id', 'name', 'description', 'l3_policy_id', 'network_id',
                    'inject_default_route']
    pagination_support = True
    sorting_support = True


class ShowL2Policy(neutronV20.ShowCommand):
    """Show information of a given L2 Policy."""

    resource = 'l2_policy'
    log = logging.getLogger(__name__ + '.ShowL2Policy')


class CreateL2Policy(neutronV20.CreateCommand):
    """Create a L2 Policy for a given tenant."""

    resource = 'l2_policy'
    log = logging.getLogger(__name__ + '.CreateL2Policy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the L2 Policy'))
        parser.add_argument(
            '--network',
            help=_('Neutron Network UUID to map the L2 Policy to '
                   '(if not specified, new Neutron Network is created '
                   'implicitly)'))
        parser.add_argument(
            '--l3-policy',
            default='',
            help=_('L3 Policy UUID (if not specified default is used)'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of L2 Policy to create (required argument)'))
        n_utils.add_boolean_argument(
            parser, '--inject-default-route', dest='inject_default_route',
            help=_('Enable or disable injecting default route, '
                   'default is True'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))
        parser.add_argument(
            '--reuse-bd',
            default=None,
            help=_('Name or UUID of L2 Policy whose BridgeDomain should '
                   'be reused (APIC only)'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description', 'shared',
                                'inject_default_route'])
        if parsed_args.l3_policy:
            body[self.resource]['l3_policy_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'l3_policy',
                    parsed_args.l3_policy)
        if parsed_args.network:
            body[self.resource]['network_id'] = (
                parsed_args.network)
        if parsed_args.reuse_bd:
            body[self.resource]['reuse_bd'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'l2_policy',
                    parsed_args.reuse_bd)
        return body


class DeleteL2Policy(neutronV20.DeleteCommand):
    """Delete a given L2 Policy."""

    resource = 'l2_policy'
    log = logging.getLogger(__name__ + '.DeleteL2Policy')


class UpdateL2Policy(neutronV20.UpdateCommand):
    """Update L2 Policy's information."""

    resource = 'l2_policy'
    log = logging.getLogger(__name__ + '.UpdateL2Policy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the L2 Policy'))
        parser.add_argument(
            '--l3-policy',
            default='',
            help=_('New L3 Policy'))
        parser.add_argument(
            '--name',
            help=_('New name of the L2 Policy'))
        n_utils.add_boolean_argument(
            parser, '--inject-default-route', dest='inject_default_route',
            help=_('Enable or disable injecting of default route'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description', 'shared',
                                'inject_default_route'])
        if parsed_args.l3_policy:
            body[self.resource]['l3_policy_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'l3_policy',
                    parsed_args.l3_policy)

        return body


class ListL3Policy(neutronV20.ListCommand):
    """List l3_policies that belong to a given tenant."""

    resource = 'l3_policy'
    log = logging.getLogger(__name__ + '.ListL3Policy')
    _formatters = {}
    list_columns = ['id', 'name', 'description', 'ip_pool',
                    'subnet_prefix_length']
    pagination_support = True
    sorting_support = True


class ShowL3Policy(neutronV20.ShowCommand):
    """Show information of a given L3 Policy."""

    resource = 'l3_policy'
    log = logging.getLogger(__name__ + '.ShowL3Policy')


class CreateL3Policy(neutronV20.CreateCommand):
    """Create a L3 Policy for a given tenant."""

    resource = 'l3_policy'
    log = logging.getLogger(__name__ + '.CreateL3Policy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the L3 Policy'))
        parser.add_argument(
            '--ip-version',
            type=int,
            # default=4, choices=[4, 6],
            help=_('IP version, default is 4'))
        parser.add_argument(
            '--ip-pool',
            help=_('CIDR of IP pool to create, default is 10.0.0.0/8'))
        parser.add_argument(
            '--subnet-prefix-length',
            type=int,
            help=_('Subnet prefix length, default is 24'))
        parser.add_argument(
            '--address-scope-v4-id',
            help=_('Neutron Address-scope v4 UUID '
                   '(if not specified, new Neutron Address-scope is '
                   'created implicitly based on ip_version)'))
        parser.add_argument(
            '--address-scope-v6-id',
            help=_('Neutron Address-scope v6 UUID '
                   '(if not specified, new Neutron Address-scope is '
                   'created implicitly based on ip_version)'))
        parser.add_argument(
            '--subnetpools-v4', type=utils.str2list,
            help=_('Comma separated list of Neutron Subnetpool v4 UUIDs '
                   'if ip_version and address scope is v4'))
        parser.add_argument(
            '--subnetpools-v6', type=utils.str2list,
            help=_('Comma separated list of Neutron Subnetpool v6 UUIDs '
                   'if ip_version and address scope is v6'))
        parser.add_argument(
            '--external-segment',
            action='append', dest='external_segments', type=utils.str2dict,
            # Note: The following format is also supported but we do not
            # show it to avoid confusion
            # help=_('Use format <ext-segment-id-1>=<ip-addr1:ipaddr2:...>'
            #        '(this option can be repeated)'))
            help=_('Comma separated list of External Segments'
                   '(this option can be repeated)'))
        parser.add_argument(
            '--routers', type=utils.str2list,
            help=_('Comma separated list of Neutron Router UUIDs'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of L3 policy to create (required argument)'))
        parser.add_argument(
            '--allowed-vm-names', type=utils.str2list,
            help=_('Comma separated list of allowed VM name regexes, each '
                   'regex can be up to 255 characters.'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.external_segments:
            external_segments_dict = {}
            for external_segment in parsed_args.external_segments:
                external_segment_id = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'external_segment',
                    external_segment.keys()[0])
                ipaddrs = external_segment.itervalues().next()
                if ipaddrs is "":
                    ipaddrs = []
                else:
                    ipaddrs = external_segment.itervalues().next().split(':')
                external_segments_dict[external_segment_id] = ipaddrs

            body[self.resource]['external_segments'] = external_segments_dict

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'ip_version', 'ip_pool',
                                'address_scope_v4_id', 'address_scope_v6_id',
                                'subnetpools_v4', 'subnetpools_v6',
                                'routers', 'subnet_prefix_length', 'shared',
                                'allowed_vm_names'])

        return body


class DeleteL3Policy(neutronV20.DeleteCommand):
    """Delete a given L3 Policy."""

    resource = 'l3_policy'
    log = logging.getLogger(__name__ + '.DeleteL3Policy')


class UpdateL3Policy(neutronV20.UpdateCommand):
    """Update L3 Policy's information."""

    resource = 'l3_policy'
    log = logging.getLogger(__name__ + '.UpdateL3Policy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the L3 Policy'))
        parser.add_argument(
            '--subnet-prefix-length',
            type=int,
            help=_('New subnet prefix length'))
        parser.add_argument(
            '--external-segment',
            action='append', dest='external_segments', type=utils.str2dict,
            # Note: The following format is also supported but we do not
            # show it to avoid confusion
            # help=_('Use format <ext-segment-id-1>=<ip-addr1:ipaddr2:...>'
            #        '(this option can be repeated)'))
            help=_('New comma separated list of External Segments'
                   '(this option can be repeated)'))
        parser.add_argument(
            '--subnetpools-v4', type=utils.str2list,
            help=_('New comma separated list of Neutron Subnetpool v4 UUIDs '
                   'if ip_version and address scope is v4'))
        parser.add_argument(
            '--subnetpools-v6', type=utils.str2list,
            help=_('New comma separated list of Neutron Subnetpool v6 UUIDs '
                   'if ip_version and address scope is v6'))
        parser.add_argument(
            '--routers', type=utils.str2list,
            help=_('New comma separated list of Neutron Router UUIDs'))
        parser.add_argument(
            '--name',
            help=_('New name of the L3 Policy'))
        parser.add_argument(
            '--allowed-vm-names', type=utils.str2list,
            help=_('Comma separated list of allowed VM name regexes, each '
                   'regex can be up to 255 characters.'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.external_segments:
            external_segments_dict = {}
            for external_segment in parsed_args.external_segments:
                if not external_segment:
                    break
                external_segment_id = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'external_segment',
                    external_segment.keys()[0])
                ipaddrs = external_segment.itervalues().next()
                if ipaddrs is "":
                    ipaddrs = []
                else:
                    ipaddrs = external_segment.itervalues().next().split(':')
                external_segments_dict[external_segment_id] = ipaddrs

            body[self.resource]['external_segments'] = external_segments_dict

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'ip_version', 'ip_pool', 'routers',
                                'subnetpools_v4', 'subnetpools_v6',
                                'subnet_prefix_length', 'shared',
                                'allowed_vm_names'])

        return body


class ListApplicationPolicyGroup(neutronV20.ListCommand):
    """List l3_policies that belong to a given tenant."""

    resource = 'application_policy_group'
    log = logging.getLogger(__name__ + '.ListApplicationPolicyGroup')
    _formatters = {}
    list_columns = ['id', 'name', 'description', 'shared']
    pagination_support = True
    sorting_support = True


class ShowApplicationPolicyGroup(neutronV20.ShowCommand):
    """Show information of a given Application Policy Group."""

    resource = 'application_policy_group'
    log = logging.getLogger(__name__ + '.ShowApplicationPolicyGroup')


class CreateApplicationPolicyGroup(neutronV20.CreateCommand):
    """Create a Application Policy Group for a given tenant."""

    resource = 'application_policy_group'
    log = logging.getLogger(__name__ + '.CreateApplicationPolicyGroup')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the Application Policy Group'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of the Application Policy Group to create '
                   '(required argument)'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'shared'])

        return body


class DeleteApplicationPolicyGroup(neutronV20.DeleteCommand):
    """Delete a given Application Policy Group."""

    resource = 'application_policy_group'
    log = logging.getLogger(__name__ + '.DeleteApplicationPolicyGroup')


class UpdateApplicationPolicyGroup(neutronV20.UpdateCommand):
    """Update Application Policy Group's information."""

    resource = 'application_policy_group'
    log = logging.getLogger(__name__ + '.UpdateApplicationPolicyGroup')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the Application Policy Group'))
        parser.add_argument(
            '--name',
            help=_('New name of the Application Policy Group'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'shared'])

        return body


class ListNetworkServicePolicy(neutronV20.ListCommand):
    """List Network Service Policies that belong to a given tenant."""

    resource = 'network_service_policy'
    log = logging.getLogger(__name__ + '.ListNetworkServicePolicy')
    _formatters = {'network_servie_params': _format_network_service_params}
    list_columns = ['id', 'name', 'description', 'network_service_params',
                    'policy_target_groups']
    pagination_support = True
    sorting_support = True


class ShowNetworkServicePolicy(neutronV20.ShowCommand):
    """Show information of a given network_service_policy."""

    resource = 'network_service_policy'
    log = logging.getLogger(__name__ + '.ShowNetworkServicePolicy')


class CreateNetworkServicePolicy(neutronV20.CreateCommand):
    """Create a Network Service Policy for a given tenant."""

    resource = 'network_service_policy'
    log = logging.getLogger(__name__ + '.CreateNetworkServicePolicy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the network_service_policy'))
        parser.add_argument(
            'name',
            help=_('Name of network_service_policy to create (required '
                   'argument)'))
        parser.add_argument(
            '--network-service-params',
            metavar='type=PARAM_TYPE,name=PARAM_NAME,value=PARAM_VALUE',
            action='append', dest='network_service_params',
            type=utils.str2dict,
            help=_('Params for this Network Service '
                   'Policy (this option can be repeated)'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'network_service_params', 'shared'])
        return body


class DeleteNetworkServicePolicy(neutronV20.DeleteCommand):
    """Delete a given network_service_policy."""

    resource = 'network_service_policy'
    log = logging.getLogger(__name__ + '.DeleteNetworkServicePolicy')


class UpdateNetworkServicePolicy(neutronV20.UpdateCommand):
    """Update network_service_policy's information."""

    resource = 'network_service_policy'
    log = logging.getLogger(__name__ + '.UpdateNetworkServicePolicy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the network_service_policy'))
        parser.add_argument(
            '--name',
            help=_('New name of the network_service_policy'))
        parser.add_argument(
            '--network-service-params',
            metavar='type=PARAM_TYPE,name=PARAM_NAME,value=PARAM_VALUE',
            action='append', dest='network_service_params',
            type=utils.str2dict,
            help=_('New params for this Network Service '
                   'Policy (this option can be repeated)'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'network_service_params', 'shared'])
        return body


class ListPolicyClassifier(neutronV20.ListCommand):
    """List classifiers that belong to a given tenant."""

    resource = 'policy_classifier'
    log = logging.getLogger(__name__ + '.ListPolicyClassifier')
    _formatters = {}
    list_columns = ['id', 'name', 'protocol', 'port_range', 'direction']
    pagination_support = True
    sorting_support = True


class ShowPolicyClassifier(neutronV20.ShowCommand):
    """Show information of a given classifier."""

    resource = 'policy_classifier'
    log = logging.getLogger(__name__ + '.ShowPolicyClassifier')


class CreatePolicyClassifier(neutronV20.CreateCommand):
    """Create a classifier for a given tenant."""

    resource = 'policy_classifier'
    log = logging.getLogger(__name__ + '.CreatePolicyClassifier')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('A description for the policy classifier'))
        parser.add_argument(
            '--protocol',
            help=_('A protocol value: tcp, udp, icmp or a protocol number '
                   'between 0 and 255. When not set, all protocols are '
                   'matched'))
        parser.add_argument(
            '--port-range',
            help=_('A port range value in the format p1[:p2]. '
                   'When not set all ports are matched'))
        parser.add_argument(
            '--direction',
            choices=['in', 'out', 'bi', ''],
            help=_('A direction value. When not set defaults to \'bi\''))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('A name for classifier to create (required argument)'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'protocol', 'port_range',
                                'direction', 'shared'])

        if 'direction' not in body[self.resource]:
            body[self.resource]['direction'] = 'bi'

        return body


class DeletePolicyClassifier(neutronV20.DeleteCommand):
    """Delete a given classifier."""

    resource = 'policy_classifier'
    log = logging.getLogger(__name__ + '.DeletePolicyClassifier')


class UpdatePolicyClassifier(neutronV20.UpdateCommand):
    """Update classifier's information."""

    resource = 'policy_classifier'
    log = logging.getLogger(__name__ + '.UpdatePolicyClassifier')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description for the policy classifier'))
        parser.add_argument(
            '--protocol',
            help=_('New protocol value: tcp, udp, icmp or a protocol number '
                   'between 0 and 255 '
                   '(use empty string \'\' to unset and match all protocols)'))
        parser.add_argument(
            '--port-range',
            help=_('New port range value in the format p1[:p2] '
                   '(use empty string \'\' to unset)'))
        parser.add_argument(
            '--direction',
            choices=['in', 'out', 'bi', ''],
            help=_('New direction value'))
        parser.add_argument(
            '--name',
            help=_('New name of the classifier'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'protocol', 'port_range',
                                'direction', 'shared'])

        if parsed_args.protocol == '':
            body[self.resource]['protocol'] = None

        if parsed_args.port_range == '':
            body[self.resource]['port_range'] = None

        return body


class ListPolicyAction(neutronV20.ListCommand):
    """List actions that belong to a given tenant."""

    resource = 'policy_action'
    log = logging.getLogger(__name__ + '.ListPolicyAction')
    _formatters = {}
    list_columns = ['id', 'name', 'action_type', 'action_value']
    pagination_support = True
    sorting_support = True


class ShowPolicyAction(neutronV20.ShowCommand):
    """Show information of a given action."""

    resource = 'policy_action'
    log = logging.getLogger(__name__ + '.ShowPolicyAction')


class CreatePolicyAction(neutronV20.CreateCommand):
    """Create a action for a given tenant."""

    resource = 'policy_action'
    log = logging.getLogger(__name__ + '.CreatePolicyAction')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the policy action'))
        parser.add_argument(
            '--action-type',
            help=_('Type of action'))
        parser.add_argument(
            '--action-value',
            help=_('Name/UUID of servicechain spec for redirect action'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of action to create (required argument)'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.action_value:
            body[self.resource]['action_value'] = (
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'servicechain_spec',
                    parsed_args.action_value))

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'action_type', 'shared'])

        return body


class DeletePolicyAction(neutronV20.DeleteCommand):
    """Delete a given action."""

    resource = 'policy_action'
    log = logging.getLogger(__name__ + '.DeletePolicyAction')


class UpdatePolicyAction(neutronV20.UpdateCommand):
    """Update action's information."""

    resource = 'policy_action'
    log = logging.getLogger(__name__ + '.UpdatePolicyAction')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the policy action'))
        parser.add_argument(
            '--action-value',
            help=_('New name/UUID of servicechain spec for redirect action'))
        parser.add_argument(
            '--name',
            help=_('New name of the action'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.action_value:
            body[self.resource]['action_value'] = (
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'servicechain_spec',
                    parsed_args.action_value))

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'shared'])

        return body


class ListPolicyRule(neutronV20.ListCommand):
    """List policy_rules that belong to a given tenant."""

    resource = 'policy_rule'
    log = logging.getLogger(__name__ + '.ListPolicyRule')
    _formatters = {}
    list_columns = ['id', 'name', 'enabled', 'classifier_id',
                    'actions']
    pagination_support = True
    sorting_support = True


class ShowPolicyRule(neutronV20.ShowCommand):
    """Show information of a given policy_rule."""

    resource = 'policy_rule'
    log = logging.getLogger(__name__ + '.ShowPolicyRule')


class CreatePolicyRule(neutronV20.CreateCommand):
    """Create a policy_rule for a given tenant."""

    resource = 'policy_rule'
    log = logging.getLogger(__name__ + '.CreatePolicyRule')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the policy_rule'))
        n_utils.add_boolean_argument(
            parser, '--enabled', dest='enabled',
            help=_('Enable flag, default is True '
                   '(if False, this Policy Rule is ignored)'))
        parser.add_argument(
            '--classifier',
            help=_('Policy Classifier (required argument)'))
        parser.add_argument(
            '--actions', type=utils.str2list,
            help=_('Comma separated list of Policy Action(s)'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of Policy Rule to create (required argument)'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.actions:
            body[self.resource]['policy_actions'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_action',
                    elem) for elem in parsed_args.actions]

        if parsed_args.classifier:
            body[self.resource]['policy_classifier_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_classifier',
                    parsed_args.classifier)

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'enabled', 'shared'])

        return body


class DeletePolicyRule(neutronV20.DeleteCommand):
    """Delete a given policy_rule."""

    resource = 'policy_rule'
    log = logging.getLogger(__name__ + '.DeletePolicyRule')


class UpdatePolicyRule(neutronV20.UpdateCommand):
    """Update policy_rule's information."""

    resource = 'policy_rule'
    log = logging.getLogger(__name__ + '.UpdatePolicyRule')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('New name of the Policy Rule'))
        parser.add_argument(
            '--description',
            help=_('New description of the Policy Rule'))
        n_utils.add_boolean_argument(
            parser, '--enabled', dest='enabled',
            help=_('Enable flag (if False, this Policy Rule is ignored)'))
        parser.add_argument(
            '--classifier',
            help=_('New Policy Classifier'))
        parser.add_argument(
            '--actions', type=utils.str2list,
            help=_('New comma separated list of Policy Actions '
                   '(to unset use "")'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.actions == []:
            body[self.resource]['policy_actions'] = []
        elif parsed_args.actions:
            body[self.resource]['policy_actions'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_action',
                    elem) for elem in parsed_args.actions]

        if parsed_args.classifier:
            body[self.resource]['policy_classifier_id'] = \
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_classifier',
                    parsed_args.classifier)

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description',
                                'enabled', 'shared'])
        return body


class ListPolicyRuleSet(neutronV20.ListCommand):
    """List policy_rule_sets that belong to a given tenant."""

    resource = 'policy_rule_set'
    log = logging.getLogger(__name__ + '.ListPolicyRuleSet')
    _formatters = {}
    list_columns = ['id', 'name', 'policy_rules']
    pagination_support = True
    sorting_support = True


class ShowPolicyRuleSet(neutronV20.ShowCommand):
    """Show information of a given policy_rule_set."""

    resource = 'policy_rule_set'
    log = logging.getLogger(__name__ + '.ShowPolicyRuleSet')


class CreatePolicyRuleSet(neutronV20.CreateCommand):
    """Create a policy rule set for a given tenant."""

    resource = 'policy_rule_set'
    log = logging.getLogger(__name__ + '.CreatePolicyRuleSet')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the policy rule set'))
        parser.add_argument(
            '--policy-rules', type=utils.str2list,
            help=_('Comma separated list of Policy Rules'))
        parser.add_argument(
            '--child-policy-rule-sets', type=utils.str2list,
            help=_('Comma separated list of child Policy Rule Sets'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of Policy Rule Set to create (required argument)'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.policy_rules:
            body[self.resource]['policy_rules'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_rule',
                    elem) for elem in parsed_args.policy_rules]

        if parsed_args.child_policy_rule_sets:
            body[self.resource]['child_policy_rule_sets'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_rule_set',
                    elem) for elem in parsed_args.child_policy_rule_sets]

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description', 'shared'])
        return body


class DeletePolicyRuleSet(neutronV20.DeleteCommand):
    """Delete a given policy rule set."""

    resource = 'policy_rule_set'
    log = logging.getLogger(__name__ + '.DeletePolicyRuleSet')


class UpdatePolicyRuleSet(neutronV20.UpdateCommand):
    """Update policy rule set's information."""

    resource = 'policy_rule_set'
    log = logging.getLogger(__name__ + '.UpdatePolicyRuleSet')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('New name of the Policy Rule Set'))
        parser.add_argument(
            '--description',
            help=_('New description of the Policy Rule Set'))
        parser.add_argument(
            '--policy-rules', type=utils.str2list,
            help=_('New comma separated list of Policy Rules '
                   '(to unset use "")'))
        parser.add_argument(
            '--child-policy-rule-sets', type=utils.str2list,
            help=_('New comma separated list of child Policy Rule Sets '
                   '(to unset use "")'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }
        if parsed_args.policy_rules == []:
            body[self.resource]['policy_rules'] = []
        elif parsed_args.policy_rules:
            body[self.resource]['policy_rules'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_rule',
                    elem) for elem in parsed_args.policy_rules]

        if parsed_args.child_policy_rule_sets == []:
            body[self.resource]['child_policy_rule_sets'] = []
        elif parsed_args.child_policy_rule_sets:
            body[self.resource]['child_policy_rule_sets'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'policy_rule_set',
                    elem) for elem in parsed_args.child_policy_rule_sets]
        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'shared'])
        return body


class ListExternalPolicy(neutronV20.ListCommand):
    """List External Policies that belong to a given tenant."""

    resource = 'external_policy'
    log = logging.getLogger(__name__ + '.ListExternalPolicy')
    list_columns = ['id', 'name', 'description', 'shared', 'external_segments']
    pagination_support = True
    sorting_support = True


class ShowExternalPolicy(neutronV20.ShowCommand):
    """Show information of a given External Policy."""

    resource = 'external_policy'
    log = logging.getLogger(__name__ + '.ShowExternalPolicy')


class CreateExternalPolicy(neutronV20.CreateCommand):
    """Create a External Policy for a given tenant."""

    resource = 'external_policy'
    log = logging.getLogger(__name__ + '.CreateExternalPolicy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the External Policy'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of External Policy to create (required argument)'))
        parser.add_argument(
            '--external-segments', type=utils.str2list,
            help=_('Comma separated list of External Segments'))
        parser.add_argument(
            '--provided-policy-rule-sets', type=utils.str2dict,
            help=_('Comma separated list of Policy Rule Sets'))
        parser.add_argument(
            '--consumed-policy-rule-sets', type=utils.str2dict,
            help=_('Comma separated list of Policy Rule Sets'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.provided_policy_rule_sets:
            for key in parsed_args.provided_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.provided_policy_rule_sets[id_key] = (
                    parsed_args.provided_policy_rule_sets.pop(key))

        if parsed_args.consumed_policy_rule_sets:
            for key in parsed_args.consumed_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.consumed_policy_rule_sets[id_key] = (
                    parsed_args.consumed_policy_rule_sets.pop(key))

        if parsed_args.external_segments:
            body[self.resource]['external_segments'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'external_segment',
                    elem) for elem in parsed_args.external_segments]

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'provided_policy_rule_sets',
                                'consumed_policy_rule_sets', 'shared'])

        return body


class DeleteExternalPolicy(neutronV20.DeleteCommand):
    """Delete a given External Policy."""

    resource = 'external_policy'
    log = logging.getLogger(__name__ + '.DeleteExternalPolicy')


class UpdateExternalPolicy(neutronV20.UpdateCommand):
    """Update External Policy's information."""

    resource = 'external_policy'
    log = logging.getLogger(__name__ + '.UpdateExternalPolicy')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the External Policy'))
        parser.add_argument(
            '--name',
            help=_('New name of the External Policy'))
        parser.add_argument(
            '--external-segments', type=utils.str2list,
            help=_('New comma separated list of External Segments '
                   '(to unset use "")'))
        parser.add_argument(
            '--provided-policy-rule-sets', type=utils.str2dict,
            help=_('New comma separated list of Policy Rule Sets '
                   '(to unset use "")'))
        parser.add_argument(
            '--consumed-policy-rule-sets', type=utils.str2dict,
            help=_('New comma separated list of Policy Rule Sets '
                   '(to unset use "")'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.provided_policy_rule_sets:
            for key in parsed_args.provided_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.provided_policy_rule_sets[id_key] = (
                    parsed_args.provided_policy_rule_sets.pop(key))

        if parsed_args.consumed_policy_rule_sets:
            for key in parsed_args.consumed_policy_rule_sets.keys():
                id_key = neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'policy_rule_set',
                    key)
                parsed_args.consumed_policy_rule_sets[id_key] = (
                    parsed_args.consumed_policy_rule_sets.pop(key))

        if parsed_args.external_segments == []:
            body[self.resource]['external_segments'] = []
        elif parsed_args.external_segments:
            body[self.resource]['external_segments'] = [
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(),
                    'external_segment',
                    elem) for elem in parsed_args.external_segments]

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'provided_policy_rule_sets',
                                'consumed_policy_rule_sets', 'shared'])

        return body


class ListExternalSegment(neutronV20.ListCommand):
    """List External Segments that belong to a given tenant."""

    resource = 'external_segment'
    log = logging.getLogger(__name__ + '.ListExternalSegment')
    _formatters = {'external_routes': _format_host_routes, }
    list_columns = ['id', 'name', 'description', 'cidr',
                    'external_routes', 'port_address_translation', 'shared']
    pagination_support = True
    sorting_support = True


class ShowExternalSegment(neutronV20.ShowCommand):
    """Show information of a given External Segment."""

    resource = 'external_segment'
    log = logging.getLogger(__name__ + '.ShowExternalSegment')


class CreateExternalSegment(neutronV20.CreateCommand):
    """Create a External Segment for a given tenant."""

    resource = 'external_segment'
    log = logging.getLogger(__name__ + '.CreateExternalSegment')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the External Segment'))
        parser.add_argument(
            'name',
            help=_('Name of External Segment to create (required argument)'))
        parser.add_argument(
            '--ip-version',
            type=int, choices=[4, 6],
            help=_('IP version, default is 4'))
        parser.add_argument(
            '--cidr',
            help=_('CIDR of External Segment, default is 172.16.0.0/12'))
        parser.add_argument(
            '--external-route', metavar='destination=CIDR,nexthop=IP_ADDR',
            action='append', dest='external_routes', type=utils.str2dict,
            help=_('If no nexthop, use format: destination=CIDR,nexthop '
                   '(this option can be repeated)'))
        n_utils.add_boolean_argument(
            parser, '--port-address-translation',
            dest='port_address_translation',
            help=_('Enable port-based address translation, default is False'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.external_routes:
            eroutes = []
            for er in parsed_args.external_routes:
                if 'nexthop' in er and er['nexthop'] == '':
                    er['nexthop'] = None
                if er:
                    eroutes.append(er)
            body['external_segment']['external_routes'] = eroutes

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'ip_version', 'cidr',
                                'port_address_translation', 'shared'])

        return body


class DeleteExternalSegment(neutronV20.DeleteCommand):
    """Delete a given External Segment."""

    resource = 'external_segment'
    log = logging.getLogger(__name__ + '.DeleteExternalSegment')


class UpdateExternalSegment(neutronV20.UpdateCommand):
    """Update External Segment's information."""

    resource = 'external_segment'
    log = logging.getLogger(__name__ + '.UpdateExternalSegment')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the External Segment'))
        parser.add_argument(
            '--name',
            help=_('New name of External Segment'))
        parser.add_argument(
            '--external-route', metavar='destination=CIDR,nexthop=IP_ADDR',
            action='append', dest='external_routes', type=utils.str2dict,
            help=_('If no nexthop, use format: destination=CIDR,nexthop '
                   '(this option can be repeated)'))
        n_utils.add_boolean_argument(
            parser, '--port-address-translation',
            dest='port_address_translation',
            help=_('Enable or disable port-based address translation'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        if parsed_args.external_routes == [{}]:
            body[self.resource]['external_routes'] = []
        elif parsed_args.external_routes:
            eroutes = []
            for er in parsed_args.external_routes:
                if 'nexthop' in er and er['nexthop'] == '':
                    er['nexthop'] = None
                if er:
                    eroutes.append(er)
            body[self.resource]['external_routes'] = eroutes

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'ip_version', 'cidr',
                                'port_address_translation', 'shared'])

        return body


class ListNatPool(neutronV20.ListCommand):
    """List NAT Pools that belong to a given tenant."""

    resource = 'nat_pool'
    log = logging.getLogger(__name__ + '.ListNatPool')
    list_columns = ['id', 'name', 'description', 'ip_pool',
                    'external_segment_id', 'shared']
    pagination_support = True
    sorting_support = True


class ShowNatPool(neutronV20.ShowCommand):
    """Show information of a given NAT Pool."""

    resource = 'nat_pool'
    log = logging.getLogger(__name__ + '.ShowNatPool')


class CreateNatPool(neutronV20.CreateCommand):
    """Create a NAT Pool for a given tenant."""

    resource = 'nat_pool'
    log = logging.getLogger(__name__ + '.CreateNatPool')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of the NAT Pool'))
        parser.add_argument(
            'name', metavar='NAME',
            help=_('Name of NAT Pool to create (required argument)'))
        parser.add_argument(
            '--ip-version',
            type=int, choices=[4, 6],
            help=_('IP version, default is 4'))
        parser.add_argument(
            '--ip-pool',
            help=_('CIDR for NAT Pool'))
        parser.add_argument(
            '--external-segment',
            help=_('External Segment'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing, default is False'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'ip_version', 'ip_pool', 'shared'])

        if parsed_args.external_segment:
            body[self.resource]['external_segment_id'] = (
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'external_segment',
                    parsed_args.external_segment))

        return body


class DeleteNatPool(neutronV20.DeleteCommand):
    """Delete a given NAT Pool."""

    resource = 'nat_pool'
    log = logging.getLogger(__name__ + '.DeleteNatPool')


class UpdateNatPool(neutronV20.UpdateCommand):
    """Update NAT Pool's information."""

    resource = 'nat_pool'
    log = logging.getLogger(__name__ + '.UpdateNatPool')

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('New description of the NAT Pool'))
        parser.add_argument(
            '--name',
            help=_('New name of NAT Pool'))
        parser.add_argument(
            '--external-segment',
            help=_('New External Segment'))
        n_utils.add_boolean_argument(
            parser, '--shared', dest='shared',
            help=_('Enable or disable resource sharing'))

    def args2body(self, parsed_args):
        body = {self.resource: {}, }

        neutronV20.update_dict(parsed_args, body[self.resource],
                               ['name', 'tenant_id', 'description',
                                'ip_version', 'ip_pool', 'shared'])

        if parsed_args.external_segment:
            body[self.resource]['external_segment_id'] = (
                neutronV20.find_resourceid_by_name_or_id(
                    self.get_client(), 'external_segment',
                    parsed_args.external_segment))

        return body
