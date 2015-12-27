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

"""
Command-line interface to the GBP APIs
"""

from __future__ import print_function

import argparse
import logging
import os
import sys

from keystoneclient.auth.identity import v2 as v2_auth
from keystoneclient.auth.identity import v3 as v3_auth
from keystoneclient import discover
from keystoneclient import exceptions as ks_exc
from keystoneclient import session
from oslo_utils import encodeutils
import six.moves.urllib.parse as urlparse

from cliff import app
from cliff import commandmanager
from neutronclient.common import clientmanager
from neutronclient.common import exceptions as exc
from neutronclient.common import utils
from neutronclient.i18n import _
from neutronclient.version import __version__

from gbpclient.gbp.v2_0 import groupbasedpolicy as gbp
from gbpclient.gbp.v2_0 import servicechain

VERSION = '2.0'
NEUTRON_API_VERSION = '2.0'
clientmanager.neutron_client.API_VERSIONS = {
    '2.0': 'gbpclient.v2_0.client.Client',
}


def run_command(cmd, cmd_parser, sub_argv):
    _argv = sub_argv
    index = -1
    values_specs = []
    if '--' in sub_argv:
        index = sub_argv.index('--')
        _argv = sub_argv[:index]
        values_specs = sub_argv[index:]
    known_args, _values_specs = cmd_parser.parse_known_args(_argv)
    cmd.values_specs = (index == -1 and _values_specs or values_specs)
    return cmd.run(known_args)


def env(*_vars, **kwargs):
    """Search for the first defined of possibly many env vars.

    Returns the first environment variable defined in vars, or
    returns the default defined in kwargs.

    """
    for v in _vars:
        value = os.environ.get(v, None)
        if value:
            return value
    return kwargs.get('default', '')


def check_non_negative_int(value):
    try:
        value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(_("invalid int value: %r") % value)
    if value < 0:
        raise argparse.ArgumentTypeError(_("input value %d is negative") %
                                         value)
    return value


COMMAND_V2 = {
    'policy-target-create': gbp.CreatePolicyTarget,
    'policy-target-delete': gbp.DeletePolicyTarget,
    'policy-target-update': gbp.UpdatePolicyTarget,
    'policy-target-list': gbp.ListPolicyTarget,
    'policy-target-show': gbp.ShowPolicyTarget,
    'policy-target-group-create': gbp.CreatePolicyTargetGroup,
    'policy-target-group-delete': gbp.DeletePolicyTargetGroup,
    'policy-target-group-update': gbp.UpdatePolicyTargetGroup,
    'policy-target-group-list': gbp.ListPolicyTargetGroup,
    'policy-target-group-show': gbp.ShowPolicyTargetGroup,
    'group-create': gbp.CreatePolicyTargetGroup,
    'group-delete': gbp.DeletePolicyTargetGroup,
    'group-update': gbp.UpdatePolicyTargetGroup,
    'group-list': gbp.ListPolicyTargetGroup,
    'group-show': gbp.ShowPolicyTargetGroup,
    'l2policy-create': gbp.CreateL2Policy,
    'l2policy-delete': gbp.DeleteL2Policy,
    'l2policy-update': gbp.UpdateL2Policy,
    'l2policy-list': gbp.ListL2Policy,
    'l2policy-show': gbp.ShowL2Policy,
    'l3policy-create': gbp.CreateL3Policy,
    'l3policy-delete': gbp.DeleteL3Policy,
    'l3policy-update': gbp.UpdateL3Policy,
    'l3policy-list': gbp.ListL3Policy,
    'l3policy-show': gbp.ShowL3Policy,
    'network-service-policy-create': gbp.CreateNetworkServicePolicy,
    'network-service-policy-delete': gbp.DeleteNetworkServicePolicy,
    'network-service-policy-update': gbp.UpdateNetworkServicePolicy,
    'network-service-policy-list': gbp.ListNetworkServicePolicy,
    'network-service-policy-show': gbp.ShowNetworkServicePolicy,
    'external-policy-create': gbp.CreateExternalPolicy,
    'external-policy-delete': gbp.DeleteExternalPolicy,
    'external-policy-update': gbp.UpdateExternalPolicy,
    'external-policy-list': gbp.ListExternalPolicy,
    'external-policy-show': gbp.ShowExternalPolicy,
    'external-segment-create': gbp.CreateExternalSegment,
    'external-segment-delete': gbp.DeleteExternalSegment,
    'external-segment-update': gbp.UpdateExternalSegment,
    'external-segment-list': gbp.ListExternalSegment,
    'external-segment-show': gbp.ShowExternalSegment,
    'nat-pool-create': gbp.CreateNatPool,
    'nat-pool-delete': gbp.DeleteNatPool,
    'nat-pool-update': gbp.UpdateNatPool,
    'nat-pool-list': gbp.ListNatPool,
    'nat-pool-show': gbp.ShowNatPool,
    'policy-classifier-create': gbp.CreatePolicyClassifier,
    'policy-classifier-delete': gbp.DeletePolicyClassifier,
    'policy-classifier-update': gbp.UpdatePolicyClassifier,
    'policy-classifier-list': gbp.ListPolicyClassifier,
    'policy-classifier-show': gbp.ShowPolicyClassifier,
    'policy-action-create': gbp.CreatePolicyAction,
    'policy-action-delete': gbp.DeletePolicyAction,
    'policy-action-update': gbp.UpdatePolicyAction,
    'policy-action-list': gbp.ListPolicyAction,
    'policy-action-show': gbp.ShowPolicyAction,
    'policy-rule-create': gbp.CreatePolicyRule,
    'policy-rule-delete': gbp.DeletePolicyRule,
    'policy-rule-update': gbp.UpdatePolicyRule,
    'policy-rule-list': gbp.ListPolicyRule,
    'policy-rule-show': gbp.ShowPolicyRule,
    'policy-rule-set-create': gbp.CreatePolicyRuleSet,
    'policy-rule-set-delete': gbp.DeletePolicyRuleSet,
    'policy-rule-set-update': gbp.UpdatePolicyRuleSet,
    'policy-rule-set-list': gbp.ListPolicyRuleSet,
    'policy-rule-set-show': gbp.ShowPolicyRuleSet,
    'service-profile-list': servicechain.ListServiceProfile,
    'service-profile-show': servicechain.ShowServiceProfile,
    'service-profile-create': servicechain.CreateServiceProfile,
    'service-profile-delete': servicechain.DeleteServiceProfile,
    'service-profile-update': servicechain.UpdateServiceProfile,
    'servicechain-node-list': servicechain.ListServiceChainNode,
    'servicechain-node-show': servicechain.ShowServiceChainNode,
    'servicechain-node-create': servicechain.CreateServiceChainNode,
    'servicechain-node-delete': servicechain.DeleteServiceChainNode,
    'servicechain-node-update': servicechain.UpdateServiceChainNode,
    'servicechain-spec-list': servicechain.ListServiceChainSpec,
    'servicechain-spec-show': servicechain.ShowServiceChainSpec,
    'servicechain-spec-create': servicechain.CreateServiceChainSpec,
    'servicechain-spec-delete': servicechain.DeleteServiceChainSpec,
    'servicechain-spec-update': servicechain.UpdateServiceChainSpec,
    'servicechain-instance-list': (
        servicechain.ListServiceChainInstance
    ),
    'servicechain-instance-show': (
        servicechain.ShowServiceChainInstance
    ),
    'servicechain-instance-create': (
        servicechain.CreateServiceChainInstance
    ),
    'servicechain-instance-delete': (
        servicechain.DeleteServiceChainInstance
    ),
    'servicechain-instance-update': (
        servicechain.UpdateServiceChainInstance
    ),
    'pt-create': gbp.CreatePolicyTarget,
    'pt-delete': gbp.DeletePolicyTarget,
    'pt-update': gbp.UpdatePolicyTarget,
    'pt-list': gbp.ListPolicyTarget,
    'pt-show': gbp.ShowPolicyTarget,
    'ptg-create': gbp.CreatePolicyTargetGroup,
    'ptg-delete': gbp.DeletePolicyTargetGroup,
    'ptg-update': gbp.UpdatePolicyTargetGroup,
    'ptg-list': gbp.ListPolicyTargetGroup,
    'ptg-show': gbp.ShowPolicyTargetGroup,
    'l2p-create': gbp.CreateL2Policy,
    'l2p-delete': gbp.DeleteL2Policy,
    'l2p-update': gbp.UpdateL2Policy,
    'l2p-list': gbp.ListL2Policy,
    'l2p-show': gbp.ShowL2Policy,
    'l3p-create': gbp.CreateL3Policy,
    'l3p-delete': gbp.DeleteL3Policy,
    'l3p-update': gbp.UpdateL3Policy,
    'l3p-list': gbp.ListL3Policy,
    'l3p-show': gbp.ShowL3Policy,
    'nsp-create': gbp.CreateNetworkServicePolicy,
    'nsp-delete': gbp.DeleteNetworkServicePolicy,
    'nsp-update': gbp.UpdateNetworkServicePolicy,
    'nsp-list': gbp.ListNetworkServicePolicy,
    'nsp-show': gbp.ShowNetworkServicePolicy,
    'ep-create': gbp.CreateExternalPolicy,
    'ep-delete': gbp.DeleteExternalPolicy,
    'ep-update': gbp.UpdateExternalPolicy,
    'ep-list': gbp.ListExternalPolicy,
    'ep-show': gbp.ShowExternalPolicy,
    'es-create': gbp.CreateExternalSegment,
    'es-delete': gbp.DeleteExternalSegment,
    'es-update': gbp.UpdateExternalSegment,
    'es-list': gbp.ListExternalSegment,
    'es-show': gbp.ShowExternalSegment,
    'np-create': gbp.CreateNatPool,
    'np-delete': gbp.DeleteNatPool,
    'np-update': gbp.UpdateNatPool,
    'np-list': gbp.ListNatPool,
    'np-show': gbp.ShowNatPool,
    'pc-create': gbp.CreatePolicyClassifier,
    'pc-delete': gbp.DeletePolicyClassifier,
    'pc-update': gbp.UpdatePolicyClassifier,
    'pc-list': gbp.ListPolicyClassifier,
    'pc-show': gbp.ShowPolicyClassifier,
    'pa-create': gbp.CreatePolicyAction,
    'pa-delete': gbp.DeletePolicyAction,
    'pa-update': gbp.UpdatePolicyAction,
    'pa-list': gbp.ListPolicyAction,
    'pa-show': gbp.ShowPolicyAction,
    'pr-create': gbp.CreatePolicyRule,
    'pr-delete': gbp.DeletePolicyRule,
    'pr-update': gbp.UpdatePolicyRule,
    'pr-list': gbp.ListPolicyRule,
    'pr-show': gbp.ShowPolicyRule,
    'prs-create': gbp.CreatePolicyRuleSet,
    'prs-delete': gbp.DeletePolicyRuleSet,
    'prs-update': gbp.UpdatePolicyRuleSet,
    'prs-list': gbp.ListPolicyRuleSet,
    'prs-show': gbp.ShowPolicyRuleSet,
    'sp-list': servicechain.ListServiceProfile,
    'sp-show': servicechain.ShowServiceProfile,
    'sp-create': servicechain.CreateServiceProfile,
    'sp-delete': servicechain.DeleteServiceProfile,
    'sp-update': servicechain.UpdateServiceProfile,
    'scn-list': servicechain.ListServiceChainNode,
    'scn-show': servicechain.ShowServiceChainNode,
    'scn-create': servicechain.CreateServiceChainNode,
    'scn-delete': servicechain.DeleteServiceChainNode,
    'scn-update': servicechain.UpdateServiceChainNode,
    'scs-list': servicechain.ListServiceChainSpec,
    'scs-show': servicechain.ShowServiceChainSpec,
    'scs-create': servicechain.CreateServiceChainSpec,
    'scs-delete': servicechain.DeleteServiceChainSpec,
    'scs-update': servicechain.UpdateServiceChainSpec,
    'sci-list': (
        servicechain.ListServiceChainInstance
    ),
    'sci-show': (
        servicechain.ShowServiceChainInstance
    ),
    'sci-create': (
        servicechain.CreateServiceChainInstance
    ),
    'sci-delete': (
        servicechain.DeleteServiceChainInstance
    ),
    'sci-update': (
        servicechain.UpdateServiceChainInstance
    ),
}

COMMANDS = {'2.0': COMMAND_V2}


class HelpAction(argparse.Action):
    """Provide a custom action so the -h and --help options
    to the main app will print a list of the commands.

    The commands are determined by checking the CommandManager
    instance, passed in as the "default" value for the action.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        outputs = []
        max_len = 0
        app = self.default
        parser.print_help(app.stdout)
        app.api_version = '2.0'  # Check this
        app.stdout.write(_('\nCommands for GBP API v%s:\n') % app.api_version)
        command_manager = app.command_manager
        for name, ep in sorted(command_manager):
            factory = ep.load()
            cmd = factory(self, None)
            one_liner = cmd.get_description().split('\n')[0]
            outputs.append((name, one_liner))
            max_len = max(len(name), max_len)
        for (name, one_liner) in outputs:
            app.stdout.write('  %s  %s\n' % (name.ljust(max_len), one_liner))
        sys.exit(0)


class GBPShell(app.App):

    # verbose logging levels
    WARNING_LEVEL = 0
    INFO_LEVEL = 1
    DEBUG_LEVEL = 2
    CONSOLE_MESSAGE_FORMAT = '%(message)s'
    DEBUG_MESSAGE_FORMAT = '%(levelname)s: %(name)s %(message)s'
    log = logging.getLogger(__name__)

    def __init__(self, apiversion):
        super(GBPShell, self).__init__(
            description=__doc__.strip(),
            version=VERSION,
            command_manager=commandmanager.CommandManager('gbp.cli'), )
        self.commands = COMMANDS
        for k, v in self.commands[apiversion].items():
            self.command_manager.add_command(k, v)

        # This is instantiated in initialize_app() only when using
        # password flow auth
        self.auth_client = None
        self.api_version = apiversion

    def build_option_parser(self, description, version):
        """Return an argparse option parser for this application.

        Subclasses may override this method to extend
        the parser with more global options.

        :param description: full description of the application
        :paramtype description: str
        :param version: version number for the application
        :paramtype version: str
        """
        parser = argparse.ArgumentParser(
            description=description,
            add_help=False, )
        parser.add_argument(
            '--version',
            action='version',
            version=__version__, )
        parser.add_argument(
            '-v', '--verbose', '--debug',
            action='count',
            dest='verbose_level',
            default=self.DEFAULT_VERBOSE_LEVEL,
            help=_('Increase verbosity of output and show tracebacks on'
                   ' errors. You can repeat this option.'))
        parser.add_argument(
            '-q', '--quiet',
            action='store_const',
            dest='verbose_level',
            const=0,
            help=_('Suppress output except warnings and errors.'))
        parser.add_argument(
            '-h', '--help',
            action=HelpAction,
            nargs=0,
            default=self,  # tricky
            help=_("Show this help message and exit."))
        parser.add_argument(
            '-r', '--retries',
            metavar="NUM",
            type=check_non_negative_int,
            default=0,
            help=_("How many times the request to the Neutron server should "
                   "be retried if it fails."))
        # FIXME(bklei): this method should come from python-keystoneclient
        self._append_global_identity_args(parser)

        return parser

    def _append_global_identity_args(self, parser):
        # FIXME(bklei): these are global identity (Keystone) arguments which
        # should be consistent and shared by all service clients. Therefore,
        # they should be provided by python-keystoneclient. We will need to
        # refactor this code once this functionality is available in
        # python-keystoneclient.
        #
        # Note: At that time we'll need to decide if we can just abandon
        #       the deprecated args (--service-type and --endpoint-type).

        parser.add_argument(
            '--os-service-type', metavar='<os-service-type>',
            default=env('OS_NETWORK_SERVICE_TYPE', default='network'),
            help=_('Defaults to env[OS_NETWORK_SERVICE_TYPE] or network.'))

        parser.add_argument(
            '--os-endpoint-type', metavar='<os-endpoint-type>',
            default=env('OS_ENDPOINT_TYPE', default='publicURL'),
            help=_('Defaults to env[OS_ENDPOINT_TYPE] or publicURL.'))

        # FIXME(bklei): --service-type is deprecated but kept in for
        # backward compatibility.
        parser.add_argument(
            '--service-type', metavar='<service-type>',
            default=env('OS_NETWORK_SERVICE_TYPE', default='network'),
            help=_('DEPRECATED! Use --os-service-type.'))

        # FIXME(bklei): --endpoint-type is deprecated but kept in for
        # backward compatibility.
        parser.add_argument(
            '--endpoint-type', metavar='<endpoint-type>',
            default=env('OS_ENDPOINT_TYPE', default='publicURL'),
            help=_('DEPRECATED! Use --os-endpoint-type.'))

        parser.add_argument(
            '--os-auth-strategy', metavar='<auth-strategy>',
            default=env('OS_AUTH_STRATEGY', default='keystone'),
            help=_('DEPRECATED! Only keystone is supported.'))

        parser.add_argument(
            '--os_auth_strategy',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os-auth-url', metavar='<auth-url>',
            default=env('OS_AUTH_URL'),
            help=_('Authentication URL, defaults to env[OS_AUTH_URL].'))
        parser.add_argument(
            '--os_auth_url',
            help=argparse.SUPPRESS)

        project_name_group = parser.add_mutually_exclusive_group()
        project_name_group.add_argument(
            '--os-tenant-name', metavar='<auth-tenant-name>',
            default=env('OS_TENANT_NAME'),
            help=_('Authentication tenant name, defaults to '
                   'env[OS_TENANT_NAME].'))
        project_name_group.add_argument(
            '--os-project-name',
            metavar='<auth-project-name>',
            default=utils.env('OS_PROJECT_NAME'),
            help='Another way to specify tenant name. '
                 'This option is mutually exclusive with '
                 ' --os-tenant-name. '
                 'Defaults to env[OS_PROJECT_NAME].')

        parser.add_argument(
            '--os_tenant_name',
            help=argparse.SUPPRESS)

        project_id_group = parser.add_mutually_exclusive_group()
        project_id_group.add_argument(
            '--os-tenant-id', metavar='<auth-tenant-id>',
            default=env('OS_TENANT_ID'),
            help=_('Authentication tenant ID, defaults to '
                   'env[OS_TENANT_ID].'))
        project_id_group.add_argument(
            '--os-project-id',
            metavar='<auth-project-id>',
            default=utils.env('OS_PROJECT_ID'),
            help='Another way to specify tenant ID. '
            'This option is mutually exclusive with '
            ' --os-tenant-id. '
            'Defaults to env[OS_PROJECT_ID].')

        parser.add_argument(
            '--os-username', metavar='<auth-username>',
            default=utils.env('OS_USERNAME'),
            help=_('Authentication username, defaults to env[OS_USERNAME].'))
        parser.add_argument(
            '--os_username',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os-user-id', metavar='<auth-user-id>',
            default=env('OS_USER_ID'),
            help=_('Authentication user ID (Env: OS_USER_ID)'))

        parser.add_argument(
            '--os_user_id',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os-user-domain-id',
            metavar='<auth-user-domain-id>',
            default=utils.env('OS_USER_DOMAIN_ID'),
            help='OpenStack user domain ID. '
            'Defaults to env[OS_USER_DOMAIN_ID].')

        parser.add_argument(
            '--os_user_domain_id',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os-user-domain-name',
            metavar='<auth-user-domain-name>',
            default=utils.env('OS_USER_DOMAIN_NAME'),
            help='OpenStack user domain name. '
                 'Defaults to env[OS_USER_DOMAIN_NAME].')

        parser.add_argument(
            '--os_user_domain_name',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os_project_id',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os_project_name',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os-project-domain-id',
            metavar='<auth-project-domain-id>',
            default=utils.env('OS_PROJECT_DOMAIN_ID'),
            help='Defaults to env[OS_PROJECT_DOMAIN_ID].')

        parser.add_argument(
            '--os-project-domain-name',
            metavar='<auth-project-domain-name>',
            default=utils.env('OS_PROJECT_DOMAIN_NAME'),
            help='Defaults to env[OS_PROJECT_DOMAIN_NAME].')

        parser.add_argument(
            '--os-cert',
            metavar='<certificate>',
            default=utils.env('OS_CERT'),
            help=_("Path of certificate file to use in SSL "
                   "connection. This file can optionally be "
                   "prepended with the private key. Defaults "
                   "to env[OS_CERT]"))

        parser.add_argument(
            '--os-cacert',
            metavar='<ca-certificate>',
            default=env('OS_CACERT', default=None),
            help=_("Specify a CA bundle file to use in "
                   "verifying a TLS (https) server certificate. "
                   "Defaults to env[OS_CACERT]"))

        parser.add_argument(
            '--os-key',
            metavar='<key>',
            default=utils.env('OS_KEY'),
            help=_("Path of client key to use in SSL "
                   "connection. This option is not necessary "
                   "if your key is prepended to your certificate "
                   "file. Defaults to env[OS_KEY]"))

        parser.add_argument(
            '--os-password', metavar='<auth-password>',
            default=utils.env('OS_PASSWORD'),
            help=_('Authentication password, defaults to env[OS_PASSWORD].'))
        parser.add_argument(
            '--os_password',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os-region-name', metavar='<auth-region-name>',
            default=env('OS_REGION_NAME'),
            help=_('Authentication region name, defaults to '
                   'env[OS_REGION_NAME].'))
        parser.add_argument(
            '--os_region_name',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--os-token', metavar='<token>',
            default=env('OS_TOKEN'),
            help=_('Authentication token, defaults to env[OS_TOKEN].'))
        parser.add_argument(
            '--os_token',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--http-timeout', metavar='<seconds>',
            default=env('OS_NETWORK_TIMEOUT', default=None), type=float,
            help=_('Timeout in seconds to wait for an HTTP response. Defaults '
                   'to env[OS_NETWORK_TIMEOUT] or None if not specified.'))

        parser.add_argument(
            '--os-url', metavar='<url>',
            default=env('OS_URL'),
            help=_('Defaults to env[OS_URL].'))
        parser.add_argument(
            '--os_url',
            help=argparse.SUPPRESS)

        parser.add_argument(
            '--insecure',
            action='store_true',
            default=env('NEUTRONCLIENT_INSECURE', default=False),
            help=_("Explicitly allow neutronclient to perform \"insecure\" "
                   "SSL (https) requests. The server's certificate will "
                   "not be verified against any certificate authorities. "
                   "This option should be used with caution."))

    def _bash_completion(self):
        """Prints all of the commands and options for bash-completion."""
        commands = set()
        options = set()
        for option, _action in self.parser._option_string_actions.items():
            options.add(option)
        for command_name, command in self.command_manager:
            commands.add(command_name)
            cmd_factory = command.load()
            cmd = cmd_factory(self, None)
            cmd_parser = cmd.get_parser('')
            for option, _action in cmd_parser._option_string_actions.items():
                options.add(option)
        print(' '.join(commands | options))

    def run(self, argv):
        """Equivalent to the main program for the application.

        :param argv: input arguments and options
        :paramtype argv: list of str
        """
        try:
            index = 0
            command_pos = -1
            help_pos = -1
            help_command_pos = -1
            for arg in argv:
                if arg == 'bash-completion':
                    self._bash_completion()
                    return 0
                if arg in self.commands[self.api_version]:
                    if command_pos == -1:
                        command_pos = index
                elif arg in ('-h', '--help'):
                    if help_pos == -1:
                        help_pos = index
                elif arg == 'help':
                    if help_command_pos == -1:
                        help_command_pos = index
                index = index + 1
            if command_pos > -1 and help_pos > command_pos:
                argv = ['help', argv[command_pos]]
            if help_command_pos > -1 and command_pos == -1:
                argv[help_command_pos] = '--help'
            self.options, remainder = self.parser.parse_known_args(argv)
            self.configure_logging()
            self.interactive_mode = not remainder
            self.initialize_app(remainder)
        except Exception as err:
            if self.options.verbose_level >= self.DEBUG_LEVEL:
                self.log.exception(unicode(err))
                raise
            else:
                self.log.error(unicode(err))
            return 1
        result = 1
        if self.interactive_mode:
            _argv = [sys.argv[0]]
            sys.argv = _argv
            result = self.interact()
        else:
            result = self.run_subcommand(remainder)
        return result

    def run_subcommand(self, argv):
        subcommand = self.command_manager.find_command(argv)
        cmd_factory, cmd_name, sub_argv = subcommand
        cmd = cmd_factory(self, self.options)
        err = None
        result = 1
        try:
            self.prepare_to_run_command(cmd)
            full_name = (cmd_name
                         if self.interactive_mode
                         else ' '.join([self.NAME, cmd_name])
                         )
            cmd_parser = cmd.get_parser(full_name)
            return run_command(cmd, cmd_parser, sub_argv)
        except Exception as err:
            if self.options.verbose_level >= self.DEBUG_LEVEL:
                self.log.exception(unicode(err))
            else:
                self.log.error(unicode(err))
            try:
                self.clean_up(cmd, result, err)
            except Exception as err2:
                if self.options.verbose_level >= self.DEBUG_LEVEL:
                    self.log.exception(unicode(err2))
                else:
                    self.log.error(_('Could not clean up: %s'), unicode(err2))
            if self.options.verbose_level >= self.DEBUG_LEVEL:
                raise
        else:
            try:
                self.clean_up(cmd, result, None)
            except Exception as err3:
                if self.options.verbose_level >= self.DEBUG_LEVEL:
                    self.log.exception(unicode(err3))
                else:
                    self.log.error(_('Could not clean up: %s'), unicode(err3))
        return result

    def authenticate_user(self):
        """Make sure the user has provided all of the authentication
        info we need.
        """
        if self.options.os_auth_strategy == 'keystone':
            if self.options.os_token or self.options.os_url:
                # Token flow auth takes priority
                if not self.options.os_token:
                    raise exc.CommandError(
                        _("You must provide a token via"
                          " either --os-token or env[OS_TOKEN]"))

                if not self.options.os_url:
                    raise exc.CommandError(
                        _("You must provide a service URL via"
                          " either --os-url or env[OS_URL]"))

            else:
                # Validate password flow auth
                project_info = (self.options.os_tenant_name or
                                self.options.os_tenant_id or
                                (self.options.os_project_name and
                                    (self.options.project_domain_name or
                                     self.options.project_domain_id)) or
                                self.options.os_project_id)

                if (not self.options.os_username
                    and not self.options.os_user_id):
                    raise exc.CommandError(
                        _("You must provide a username or user ID via"
                          "  --os-username, env[OS_USERNAME] or"
                          "  --os-user_id, env[OS_USER_ID]"))

                if not self.options.os_password:
                    raise exc.CommandError(
                        _("You must provide a password via"
                          " either --os-password or env[OS_PASSWORD]"))

                if (not project_info):
                    # tenent is deprecated in Keystone v3. Use the latest
                    # terminology instead.
                    raise exc.CommandError(
                        _("You must provide a project_id or project_name ("
                          "with project_domain_name or project_domain_id) "
                          "via "
                          "  --os-project-id (env[OS_PROJECT_ID])"
                          "  --os-project-name (env[OS_PROJECT_NAME]),"
                          "  --os-project-domain-id "
                          "(env[OS_PROJECT_DOMAIN_ID])"
                          "  --os-project-domain-name "
                          "(env[OS_PROJECT_DOMAIN_NAME])"))

                if not self.options.os_auth_url:
                    raise exc.CommandError(
                        _("You must provide an auth url via"
                          " either --os-auth-url or via env[OS_AUTH_URL]"))
        else:   # not keystone
            if not self.options.os_url:
                raise exc.CommandError(
                    _("You must provide a service URL via"
                      " either --os-url or env[OS_URL]"))

        auth_session = self._get_keystone_session()

        self.client_manager = clientmanager.ClientManager(
            token=self.options.os_token,
            url=self.options.os_url,
            auth_url=self.options.os_auth_url,
            tenant_name=self.options.os_tenant_name,
            tenant_id=self.options.os_tenant_id,
            username=self.options.os_username,
            user_id=self.options.os_user_id,
            password=self.options.os_password,
            region_name=self.options.os_region_name,
            api_version=self.api_version,
            auth_strategy=self.options.os_auth_strategy,
            # FIXME (bklei) honor deprecated service_type and
            # endpoint type until they are removed
            service_type=self.options.os_service_type or
            self.options.service_type,
            endpoint_type=self.options.os_endpoint_type or self.endpoint_type,
            insecure=self.options.insecure,
            ca_cert=self.options.os_cacert,
            timeout=self.options.http_timeout,
            retries=self.options.retries,
            raise_errors=False,
            session=auth_session,
            auth=auth_session.auth,
            log_credentials=True)
        return

    def initialize_app(self, argv):
        """Global app init bits:

        * set up API versions
        * validate authentication info
        """

        super(GBPShell, self).initialize_app(argv)

        self.api_version = {'network': self.api_version}

        # If the user is not asking for help, make sure they
        # have given us auth.
        cmd_name = None
        if argv:
            cmd_info = self.command_manager.find_command(argv)
            cmd_factory, cmd_name, sub_argv = cmd_info
        if self.interactive_mode or cmd_name != 'help':
            self.authenticate_user()

    def clean_up(self, cmd, result, err):
        self.log.debug('clean_up %s', cmd.__class__.__name__)
        if err:
            self.log.debug('Got an error: %s', unicode(err))

    def configure_logging(self):
        """Create logging handlers for any log output."""
        root_logger = logging.getLogger('')

        # Set up logging to a file
        root_logger.setLevel(logging.DEBUG)

        # Send higher-level messages to the console via stderr
        console = logging.StreamHandler(self.stderr)
        console_level = {self.WARNING_LEVEL: logging.WARNING,
                         self.INFO_LEVEL: logging.INFO,
                         self.DEBUG_LEVEL: logging.DEBUG,
                         }.get(self.options.verbose_level, logging.DEBUG)
        console.setLevel(console_level)
        if logging.DEBUG == console_level:
            formatter = logging.Formatter(self.DEBUG_MESSAGE_FORMAT)
        else:
            formatter = logging.Formatter(self.CONSOLE_MESSAGE_FORMAT)
        logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
        console.setFormatter(formatter)
        root_logger.addHandler(console)
        return

    def get_v2_auth(self, v2_auth_url):
        return v2_auth.Password(
            v2_auth_url,
            username=self.options.os_username,
            password=self.options.os_password,
            tenant_id=self.options.os_tenant_id,
            tenant_name=self.options.os_tenant_name)

    def get_v3_auth(self, v3_auth_url):
        project_id = self.options.os_project_id or self.options.os_tenant_id
        project_name = (self.options.os_project_name or
                        self.options.os_tenant_name)

        return v3_auth.Password(
            v3_auth_url,
            username=self.options.os_username,
            password=self.options.os_password,
            user_id=self.options.os_user_id,
            user_domain_name=self.options.os_user_domain_name,
            user_domain_id=self.options.os_user_domain_id,
            project_id=project_id,
            project_name=project_name,
            project_domain_name=self.options.os_project_domain_name,
            project_domain_id=self.options.os_project_domain_id
        )

    def _discover_auth_versions(self, session, auth_url):
        # discover the API versions the server is supporting base on the
        # given URL
        try:
            ks_discover = discover.Discover(session=session, auth_url=auth_url)
            return (ks_discover.url_for('2.0'), ks_discover.url_for('3.0'))
        except ks_exc.ClientException:
            # Identity service may not support discover API version.
            # Lets try to figure out the API version from the original URL.
            url_parts = urlparse.urlparse(auth_url)
            (scheme, netloc, path, params, query, fragment) = url_parts
            path = path.lower()
            if path.startswith('/v3'):
                return (None, auth_url)
            elif path.startswith('/v2'):
                return (auth_url, None)
            else:
                # not enough information to determine the auth version
                msg = _('Unable to determine the Keystone version '
                        'to authenticate with using the given '
                        'auth_url. Identity service may not support API '
                        'version discovery. Please provide a versioned '
                        'auth_url instead.')
                raise exc.CommandError(msg)

    def _get_keystone_session(self):
        # first create a Keystone session
        cacert = self.options.os_cacert or None
        cert = self.options.os_cert or None
        key = self.options.os_key or None
        insecure = self.options.insecure or False
        ks_session = session.Session.construct(dict(cacert=cacert,
                                                    cert=cert,
                                                    key=key,
                                                    insecure=insecure))
        # discover the supported keystone versions using the given url
        (v2_auth_url, v3_auth_url) = self._discover_auth_versions(
            session=ks_session,
            auth_url=self.options.os_auth_url)

        # Determine which authentication plugin to use. First inspect the
        # auth_url to see the supported version. If both v3 and v2 are
        # supported, then use the highest version if possible.
        user_domain_name = self.options.os_user_domain_name or None
        user_domain_id = self.options.os_user_domain_id or None
        project_domain_name = self.options.os_project_domain_name or None
        project_domain_id = self.options.os_project_domain_id or None
        domain_info = (user_domain_name or user_domain_id or
                       project_domain_name or project_domain_id)

        if (v2_auth_url and not domain_info) or not v3_auth_url:
            ks_session.auth = self.get_v2_auth(v2_auth_url)
        else:
            ks_session.auth = self.get_v3_auth(v3_auth_url)

        return ks_session


def main(argv=sys.argv[1:]):
    try:
        return GBPShell(NEUTRON_API_VERSION).run(map(encodeutils.safe_decode,
                                                     argv))
    except exc.NeutronClientException:
        return 1
    except Exception as e:
        print(unicode(e))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
