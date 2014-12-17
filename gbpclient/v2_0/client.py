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
import time
import urllib

from neutronclient import client
from neutronclient.common import _
from neutronclient.common import constants
from neutronclient.common import exceptions
from neutronclient.common import serializer
from neutronclient.common import utils
import requests
import six.moves.urllib.parse as urlparse


_logger = logging.getLogger(__name__)


def exception_handler_v20(status_code, error_content):
    """Exception handler for API v2.0 client

        This routine generates the appropriate
        Neutron exception according to the contents of the
        response body

        :param status_code: HTTP error status code
        :param error_content: deserialized body of error response
    """
    error_dict = None
    if isinstance(error_content, dict):
        error_dict = error_content.get('NeutronError')
    # Find real error type
    bad_neutron_error_flag = False
    if error_dict:
        # If Neutron key is found, it will definitely contain
        # a 'message' and 'type' keys?
        try:
            error_type = error_dict['type']
            error_message = error_dict['message']
            if error_dict['detail']:
                error_message += "\n" + error_dict['detail']
        except Exception:
            bad_neutron_error_flag = True
        if not bad_neutron_error_flag:
            # If corresponding exception is defined, use it.
            client_exc = getattr(exceptions, '%sClient' % error_type, None)
            # Otherwise look up per status-code client exception
            if not client_exc:
                client_exc = exceptions.HTTP_EXCEPTION_MAP.get(status_code)
            if client_exc:
                raise client_exc(message=error_message,
                                 status_code=status_code)
            else:
                raise exceptions.NeutronClientException(
                    status_code=status_code, message=error_message)
        else:
            raise exceptions.NeutronClientException(status_code=status_code,
                                                    message=error_dict)
    else:
        message = None
        if isinstance(error_content, dict):
            message = error_content.get('message')
        if message:
            raise exceptions.NeutronClientException(status_code=status_code,
                                                    message=message)

    # If we end up here the exception was not a neutron error
    msg = "%s-%s" % (status_code, error_content)
    raise exceptions.NeutronClientException(status_code=status_code,
                                            message=msg)


class APIParamsCall(object):
    """A Decorator to add support for format and tenant overriding
       and filters
    """
    def __init__(self, function):
        self.function = function

    def __get__(self, instance, owner):
        def with_params(*args, **kwargs):
            _format = instance.format
            if 'format' in kwargs:
                instance.format = kwargs['format']
            ret = self.function(instance, *args, **kwargs)
            instance.format = _format
            return ret
        return with_params


class Client(object):
    """Client for the GBP API.

    :param string username: Username for authentication. (optional)
    :param string user_id: User ID for authentication. (optional)
    :param string password: Password for authentication. (optional)
    :param string token: Token for authentication. (optional)
    :param string tenant_name: Tenant name. (optional)
    :param string tenant_id: Tenant id. (optional)
    :param string auth_url: Keystone service endpoint for authorization.
    :param string service_type: Network service type to pull from the
                                keystone catalog (e.g. 'network') (optional)
    :param string endpoint_type: Network service endpoint type to pull from the
                                 keystone catalog (e.g. 'publicURL',
                                 'internalURL', or 'adminURL') (optional)
    :param string region_name: Name of a region to select when choosing an
                               endpoint from the service catalog.
    :param string endpoint_url: A user-supplied endpoint URL for the neutron
                            service.  Lazy-authentication is possible for API
                            service calls if endpoint is set at
                            instantiation.(optional)
    :param integer timeout: Allows customization of the timeout for client
                            http requests. (optional)
    :param bool insecure: SSL certificate validation. (optional)
    :param string ca_cert: SSL CA bundle file to use. (optional)
    :param integer retries: How many times idempotent (GET, PUT, DELETE)
                            requests to Neutron server should be retried if
                            they fail (default: 0).
    :param bool raise_errors: If True then exceptions caused by connection
                              failure are propagated to the caller.
                              (default: True)
    :param session: Keystone client auth session to use. (optional)
    :param auth: Keystone auth plugin to use. (optional)

    Example::

        from gbpclient.v2_0 import client
        gbp = client.Client(username=USER,
                            password=PASS,
                            tenant_name=TENANT_NAME,
                            auth_url=KEYSTONE_URL)

        ptgs = gbp.list_policy_target_groups()
        ...

    """

    policy_targets_path = "/grouppolicy/policy_targets"
    policy_target_path = "/grouppolicy/policy_targets/%s"
    policy_target_groups_path = "/grouppolicy/policy_target_groups"
    policy_target_group_path = "/grouppolicy/policy_target_groups/%s"
    l2_policies_path = "/grouppolicy/l2_policies"
    l2_policy_path = "/grouppolicy/l2_policies/%s"
    l3_policies_path = "/grouppolicy/l3_policies"
    l3_policy_path = "/grouppolicy/l3_policies/%s"
    network_service_policies_path = "/grouppolicy/network_service_policies"
    network_service_policy_path = "/grouppolicy/network_service_policies/%s"
    external_policies_path = "/grouppolicy/external_policies"
    external_policy_path = "/grouppolicy/external_policies/%s"
    external_segments_path = "/grouppolicy/external_segments"
    external_segment_path = "/grouppolicy/external_segments/%s"
    nat_pools_path = "/grouppolicy/nat_pools"
    nat_pool_path = "/grouppolicy/nat_pools/%s"
    policy_classifiers_path = "/grouppolicy/policy_classifiers"
    policy_classifier_path = "/grouppolicy/policy_classifiers/%s"
    policy_actions_path = "/grouppolicy/policy_actions"
    policy_action_path = "/grouppolicy/policy_actions/%s"
    policy_rules_path = "/grouppolicy/policy_rules"
    policy_rule_path = "/grouppolicy/policy_rules/%s"
    policy_rule_sets_path = "/grouppolicy/policy_rule_sets"
    policy_rule_set_path = "/grouppolicy/policy_rule_sets/%s"
    servicechain_nodes_path = "/servicechain/servicechain_nodes"
    servicechain_node_path = "/servicechain/servicechain_nodes/%s"
    servicechain_specs_path = "/servicechain/servicechain_specs"
    servicechain_spec_path = "/servicechain/servicechain_specs/%s"
    servicechain_instances_path = "/servicechain/servicechain_instances"
    servicechain_instance_path = "/servicechain/servicechain_instances/%s"

    # API has no way to report plurals, so we have to hard code them
    EXTED_PLURALS = {'policy_targets': 'policy_target',
                     'policy_target_groups': 'policy_target_group',
                     'l2_policies': 'l2_policy',
                     'l3_policies': 'l3_policy',
                     'network_service_policies': 'network_service_policy',
                     'external_policies': 'external_policy',
                     'external_segments': 'external_segment',
                     'nat_pools': 'nat_pool',
                     'policy_classifiers': 'policy_classifier',
                     'policy_actions': 'policy_action',
                     'policy_rules': 'policy_rule',
                     'policy_rule_sets': 'policy_rule_set',
                     }
    # 8192 Is the default max URI len for eventlet.wsgi.server
    MAX_URI_LEN = 8192

    def get_attr_metadata(self):
        if self.format == 'json':
            return {}
        old_request_format = self.format
        self.format = 'json'
        exts = self.list_extensions()['extensions']
        self.format = old_request_format
        ns = dict([(ext['alias'], ext['namespace']) for ext in exts])
        self.EXTED_PLURALS.update(constants.PLURALS)
        return {'plurals': self.EXTED_PLURALS,
                'xmlns': constants.XML_NS_V20,
                constants.EXT_NS: ns}

    @APIParamsCall
    def list_extensions(self, **_params):
        """Fetch a list of all exts on server side."""
        return self.get(self.extensions_path, params=_params)

    @APIParamsCall
    def show_extension(self, ext_alias, **_params):
        """Fetch a list of all exts on server side."""
        return self.get(self.extension_path % ext_alias, params=_params)

    @APIParamsCall
    def list_policy_targets(self, retrieve_all=True, **_params):
        """Fetches a list of all policy targets for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('policy_targets', self.policy_targets_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_policy_target(self, policy_target, **_params):
        """Fetches information of a certain policy target."""
        return self.get(self.policy_target_path % (policy_target),
                        params=_params)

    @APIParamsCall
    def create_policy_target(self, body=None):
        """Creates a new policy target."""
        return self.post(self.policy_targets_path, body=body)

    @APIParamsCall
    def update_policy_target(self, policy_target, body=None):
        """Updates a policy target."""
        return self.put(self.policy_target_path % (policy_target), body=body)

    @APIParamsCall
    def delete_policy_target(self, policy_target):
        """Deletes the specified policy target."""
        return self.delete(self.policy_target_path % (policy_target))

    @APIParamsCall
    def list_policy_target_groups(self, retrieve_all=True, **_params):
        """Fetches a list of all policy target_groups for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('policy_target_groups',
                         self.policy_target_groups_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_policy_target_group(self, policy_target_group, **_params):
        """Fetches information of a certain policy target_group."""
        return self.get(self.policy_target_group_path % (policy_target_group),
                        params=_params)

    @APIParamsCall
    def create_policy_target_group(self, body=None):
        """Creates a new policy target_group."""
        return self.post(self.policy_target_groups_path, body=body)

    @APIParamsCall
    def update_policy_target_group(self, policy_target_group, body=None):
        """Updates a policy target_group."""
        return self.put(self.policy_target_group_path % (policy_target_group),
                        body=body)

    @APIParamsCall
    def delete_policy_target_group(self, policy_target_group):
        """Deletes the specified policy target_group."""
        return self.delete(
            self.policy_target_group_path % (policy_target_group))

    @APIParamsCall
    def list_l2_policies(self, retrieve_all=True, **_params):
        """Fetches a list of all l2_policies for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('l2_policies', self.l2_policies_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_l2_policy(self, l2_policy, **_params):
        """Fetches information of a certain l2_policy."""
        return self.get(self.l2_policy_path % (l2_policy),
                        params=_params)

    @APIParamsCall
    def create_l2_policy(self, body=None):
        """Creates a new l2_policy."""
        return self.post(self.l2_policies_path, body=body)

    @APIParamsCall
    def update_l2_policy(self, l2_policy, body=None):
        """Updates a l2_policy."""
        return self.put(self.l2_policy_path % (l2_policy), body=body)

    @APIParamsCall
    def delete_l2_policy(self, l2_policy):
        """Deletes the specified l2_policy."""
        return self.delete(self.l2_policy_path % (l2_policy))

    @APIParamsCall
    def list_network_service_policies(self, retrieve_all=True, **_params):
        """Fetches a list of all network_service_policies for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('network_service_policies',
                         self.network_service_policies_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_network_service_policy(self, network_service_policy, **_params):
        """Fetches information of a certain network_service_policy."""
        return self.get(
            self.network_service_policy_path % (network_service_policy),
            params=_params)

    @APIParamsCall
    def create_network_service_policy(self, body=None):
        """Creates a new network_service_policy."""
        return self.post(self.network_service_policies_path, body=body)

    @APIParamsCall
    def update_network_service_policy(self, network_service_policy, body=None):
        """Updates a network_service_policy."""
        return self.put(
            self.network_service_policy_path % (network_service_policy),
            body=body)

    @APIParamsCall
    def delete_network_service_policy(self, network_service_policy):
        """Deletes the specified network_service_policy."""
        return self.delete(
            self.network_service_policy_path % (network_service_policy))

    @APIParamsCall
    def list_external_policies(self, retrieve_all=True, **_params):
        """Fetches a list of all external_policies for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('external_policies',
                         self.external_policies_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_external_policy(self, external_policy, **_params):
        """Fetches information of a certain external_policy."""
        return self.get(
            self.external_policy_path % (external_policy),
            params=_params)

    @APIParamsCall
    def create_external_policy(self, body=None):
        """Creates a new external_policy."""
        return self.post(self.external_policies_path, body=body)

    @APIParamsCall
    def update_external_policy(self, external_policy, body=None):
        """Updates a external_policy."""
        return self.put(
            self.external_policy_path % (external_policy),
            body=body)

    @APIParamsCall
    def delete_external_policy(self, external_policy):
        """Deletes the specified external_policy."""
        return self.delete(
            self.external_policy_path % (external_policy))

    @APIParamsCall
    def list_external_segments(self, retrieve_all=True, **_params):
        """Fetches a list of all external_segments for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('external_segments',
                         self.external_segments_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_external_segment(self, external_segment, **_params):
        """Fetches information of a certain external_segment."""
        return self.get(
            self.external_segment_path % (external_segment),
            params=_params)

    @APIParamsCall
    def create_external_segment(self, body=None):
        """Creates a new external_segment."""
        return self.post(self.external_segments_path, body=body)

    @APIParamsCall
    def update_external_segment(self, external_segment, body=None):
        """Updates a external_segment."""
        return self.put(
            self.external_segment_path % (external_segment),
            body=body)

    @APIParamsCall
    def delete_external_segment(self, external_segment):
        """Deletes the specified external_segment."""
        return self.delete(
            self.external_segment_path % (external_segment))

    @APIParamsCall
    def list_nat_pools(self, retrieve_all=True, **_params):
        """Fetches a list of all nat_pools for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('nat_pools',
                         self.nat_pools_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_nat_pool(self, nat_pool, **_params):
        """Fetches information of a certain nat_pool."""
        return self.get(self.nat_pool_path % (nat_pool), params=_params)

    @APIParamsCall
    def create_nat_pool(self, body=None):
        """Creates a new nat_pool."""
        return self.post(self.nat_pools_path, body=body)

    @APIParamsCall
    def update_nat_pool(self, nat_pool, body=None):
        """Updates a nat_pool."""
        return self.put(self.nat_pool_path % (nat_pool), body=body)

    @APIParamsCall
    def delete_nat_pool(self, nat_pool):
        """Deletes the specified nat_pool."""
        return self.delete(self.nat_pool_path % (nat_pool))

    @APIParamsCall
    def list_l3_policies(self, retrieve_all=True, **_params):
        """Fetches a list of all l3_policies for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('l3_policies', self.l3_policies_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_l3_policy(self, l3_policy, **_params):
        """Fetches information of a certain l3_policy."""
        return self.get(self.l3_policy_path % (l3_policy),
                        params=_params)

    @APIParamsCall
    def create_l3_policy(self, body=None):
        """Creates a new l3_policy."""
        return self.post(self.l3_policies_path, body=body)

    @APIParamsCall
    def update_l3_policy(self, l3_policy, body=None):
        """Updates a l3_policy."""
        return self.put(self.l3_policy_path % (l3_policy),
                        body=body)

    @APIParamsCall
    def delete_l3_policy(self, l3_policy):
        """Deletes the specified l3_policy."""
        return self.delete(self.l3_policy_path % (l3_policy))

    @APIParamsCall
    def list_policy_classifiers(self, retrieve_all=True, **_params):
        """Fetches a list of all policy_classifiers for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('policy_classifiers', self.policy_classifiers_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_policy_classifier(self, policy_classifier, **_params):
        """Fetches information of a certain policy_classifier."""
        return self.get(self.policy_classifier_path % (policy_classifier),
                        params=_params)

    @APIParamsCall
    def create_policy_classifier(self, body=None):
        """Creates a new policy_classifier."""
        return self.post(self.policy_classifiers_path, body=body)

    @APIParamsCall
    def update_policy_classifier(self, policy_classifier, body=None):
        """Updates a policy_classifier."""
        return self.put(self.policy_classifier_path % (policy_classifier),
                        body=body)

    @APIParamsCall
    def delete_policy_classifier(self, policy_classifier):
        """Deletes the specified policy_classifier."""
        return self.delete(self.policy_classifier_path % (policy_classifier))

    @APIParamsCall
    def list_policy_actions(self, retrieve_all=True, **_params):
        """Fetches a list of all policy_actions for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('policy_actions', self.policy_actions_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_policy_action(self, policy_action, **_params):
        """Fetches information of a certain policy_action."""
        return self.get(self.policy_action_path % (policy_action),
                        params=_params)

    @APIParamsCall
    def create_policy_action(self, body=None):
        """Creates a new policy_action."""
        return self.post(self.policy_actions_path, body=body)

    @APIParamsCall
    def update_policy_action(self, policy_action, body=None):
        """Updates a policy_action."""
        return self.put(self.policy_action_path % (policy_action), body=body)

    @APIParamsCall
    def delete_policy_action(self, policy_action):
        """Deletes the specified policy_action."""
        return self.delete(self.policy_action_path % (policy_action))

    @APIParamsCall
    def list_policy_rules(self, retrieve_all=True, **_params):
        """Fetches a list of all policy_rules for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('policy_rules', self.policy_rules_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_policy_rule(self, policy_rule, **_params):
        """Fetches information of a certain policy_rule."""
        return self.get(self.policy_rule_path % (policy_rule), params=_params)

    @APIParamsCall
    def create_policy_rule(self, body=None):
        """Creates a new policy_rule."""
        return self.post(self.policy_rules_path, body=body)

    @APIParamsCall
    def update_policy_rule(self, policy_rule, body=None):
        """Updates a policy_rule."""
        return self.put(self.policy_rule_path % (policy_rule), body=body)

    @APIParamsCall
    def delete_policy_rule(self, policy_rule):
        """Deletes the specified policy_rule."""
        return self.delete(self.policy_rule_path % (policy_rule))

    @APIParamsCall
    def list_policy_rule_sets(self, retrieve_all=True, **_params):
        """Fetches a list of all Policy Rule Sets for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('policy_rule_sets', self.policy_rule_sets_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_policy_rule_set(self, policy_rule_set, **_params):
        """Fetches information of a certain Policy Rule Set."""
        return self.get(self.policy_rule_set_path % (policy_rule_set),
                        params=_params)

    @APIParamsCall
    def create_policy_rule_set(self, body=None):
        """Creates a new Policy Rule Set."""
        return self.post(self.policy_rule_sets_path, body=body)

    @APIParamsCall
    def update_policy_rule_set(self, policy_rule_set, body=None):
        """Updates a Policy Rule Set."""
        return self.put(self.policy_rule_set_path % (policy_rule_set),
                        body=body)

    @APIParamsCall
    def delete_policy_rule_set(self, policy_rule_set):
        """Deletes the specified Policy Rule Set."""
        return self.delete(self.policy_rule_set_path % (policy_rule_set))

    def list_servicechain_nodes(self, retrieve_all=True, **_params):

        """Fetches a list of all service chain nodes for a tenant."""
        # Pass filters in "params" argument to do_request

        return self.list('servicechain_nodes', self.servicechain_nodes_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_servicechain_node(self, servicechain_node, **_params):
        """Fetches information of a certain service chain node."""
        return self.get(self.servicechain_node_path % (servicechain_node),
                        params=_params)

    @APIParamsCall
    def create_servicechain_node(self, body=None):
        """Creates a new service chain node."""
        return self.post(self.servicechain_nodes_path, body=body)

    @APIParamsCall
    def update_servicechain_node(self, servicechain_node, body=None):
        """Updates a service chain node."""
        return self.put(self.servicechain_node_path % (servicechain_node),
                        body=body)

    @APIParamsCall
    def delete_servicechain_node(self, servicechain_node):
        """Deletes the specified service chain node."""
        return self.delete(self.servicechain_node_path % (servicechain_node))

    @APIParamsCall
    def list_servicechain_specs(self, retrieve_all=True, **_params):
        """Fetches a list of all service chain specs for a tenant."""
        # Pass filters in "params" argument to do_request

        return self.list('servicechain_specs', self.servicechain_specs_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_servicechain_spec(self, servicechain_spec, **_params):
        """Fetches information of a certain service chain spec."""
        return self.get(self.servicechain_spec_path % (servicechain_spec),
                        params=_params)

    @APIParamsCall
    def create_servicechain_spec(self, body=None):
        """Creates a new service chain spec."""
        return self.post(self.servicechain_specs_path, body=body)

    @APIParamsCall
    def update_servicechain_spec(self, servicechain_spec, body=None):
        """Updates a service chain spec."""
        return self.put(self.servicechain_spec_path % (servicechain_spec),
                        body=body)

    @APIParamsCall
    def delete_servicechain_spec(self, servicechain_spec):
        """Deletes the specified service chain spec."""
        return self.delete(self.servicechain_spec_path % (servicechain_spec))

    @APIParamsCall
    def list_servicechain_instances(self, retrieve_all=True, **_params):
        """Fetches a list of all service chain instances for a tenant."""
        # Pass filters in "params" argument to do_request

        return self.list('servicechain_instances',
                         self.servicechain_instances_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_servicechain_instance(self, servicechain_instance, **_params):
        """Fetches information of a certain service chain instance."""
        return self.get(self.servicechain_instance_path %
                        (servicechain_instance), params=_params)

    @APIParamsCall
    def create_servicechain_instance(self, body=None):
        """Creates a new service chain instance."""
        return self.post(self.servicechain_instances_path, body=body)

    @APIParamsCall
    def update_servicechain_instance(self, servicechain_instance, body=None):
        """Updates a service chain instance."""
        return self.put(self.servicechain_instance_path %
                        (servicechain_instance), body=body)

    @APIParamsCall
    def delete_servicechain_instance(self, servicechain_instance):
        """Deletes the specified service chain instance."""
        return self.delete(self.servicechain_instance_path %
                           (servicechain_instance))

    def __init__(self, **kwargs):
        """Initialize a new client for the GBP v2.0 API."""
        super(Client, self).__init__()
        self.retries = kwargs.pop('retries', 0)
        self.raise_errors = kwargs.pop('raise_errors', True)
        self.httpclient = client.construct_http_client(**kwargs)
        self.version = '2.0'
        self.format = 'json'
        self.action_prefix = "/v%s" % (self.version)
        self.retry_interval = 1

    def _handle_fault_response(self, status_code, response_body):
        # Create exception with HTTP status code and message
        _logger.debug("Error message: %s", response_body)
        # Add deserialized error message to exception arguments
        try:
            des_error_body = self.deserialize(response_body, status_code)
        except Exception:
            # If unable to deserialized body it is probably not a
            # Neutron error
            des_error_body = {'message': response_body}
        # Raise the appropriate exception
        exception_handler_v20(status_code, des_error_body)

    def _check_uri_length(self, action):
        uri_len = len(self.httpclient.endpoint_url) + len(action)
        if uri_len > self.MAX_URI_LEN:
            raise exceptions.RequestURITooLong(
                excess=uri_len - self.MAX_URI_LEN)

    def do_request(self, method, action, body=None, headers=None, params=None):
        # Add format and tenant_id
        action += ".%s" % self.format
        action = self.action_prefix + action
        if type(params) is dict and params:
            params = utils.safe_encode_dict(params)
            action += '?' + urllib.urlencode(params, doseq=1)
        # Ensure client always has correct uri - do not guesstimate anything
        self.httpclient.authenticate_and_fetch_endpoint_url()
        self._check_uri_length(action)

        if body:
            body = self.serialize(body)
        self.httpclient.content_type = self.content_type()
        resp, replybody = self.httpclient.do_request(action, method, body=body)
        status_code = resp.status_code
        if status_code in (requests.codes.ok,
                           requests.codes.created,
                           requests.codes.accepted,
                           requests.codes.no_content):
            return self.deserialize(replybody, status_code)
        else:
            if not replybody:
                replybody = resp.reason
            self._handle_fault_response(status_code, replybody)

    def get_auth_info(self):
        return self.httpclient.get_auth_info()

    def serialize(self, data):
        """Serializes a dictionary into either XML or JSON.

        A dictionary with a single key can be passed and
        it can contain any structure.
        """
        if data is None:
            return None
        elif type(data) is dict:
            return serializer.Serializer(
                self.get_attr_metadata()).serialize(data, self.content_type())
        else:
            raise Exception(_("Unable to serialize object of type = '%s'") %
                            type(data))

    def deserialize(self, data, status_code):
        """Deserializes an XML or JSON string into a dictionary."""
        if status_code == 204:
            return data
        return serializer.Serializer(self.get_attr_metadata()).deserialize(
            data, self.content_type())['body']

    def content_type(self, _format=None):
        """Returns the mime-type for either 'xml' or 'json'.

        Defaults to the currently set format.
        """
        _format = _format or self.format
        return "application/%s" % (_format)

    def retry_request(self, method, action, body=None,
                      headers=None, params=None):
        """Call do_request with the default retry configuration.

        Only idempotent requests should retry failed connection attempts.
        :raises: ConnectionFailed if the maximum # of retries is exceeded
        """
        max_attempts = self.retries + 1
        for i in range(max_attempts):
            try:
                return self.do_request(method, action, body=body,
                                       headers=headers, params=params)
            except exceptions.ConnectionFailed:
                # Exception has already been logged by do_request()
                if i < self.retries:
                    _logger.debug('Retrying connection to Neutron service')
                    time.sleep(self.retry_interval)
                elif self.raise_errors:
                    raise

        if self.retries:
            msg = (_("Failed to connect to Neutron server after %d attempts")
                   % max_attempts)
        else:
            msg = _("Failed to connect Neutron server")

        raise exceptions.ConnectionFailed(reason=msg)

    def delete(self, action, body=None, headers=None, params=None):
        return self.retry_request("DELETE", action, body=body,
                                  headers=headers, params=params)

    def get(self, action, body=None, headers=None, params=None):
        return self.retry_request("GET", action, body=body,
                                  headers=headers, params=params)

    def post(self, action, body=None, headers=None, params=None):
        # Do not retry POST requests to avoid the orphan objects problem.
        return self.do_request("POST", action, body=body,
                               headers=headers, params=params)

    def put(self, action, body=None, headers=None, params=None):
        return self.retry_request("PUT", action, body=body,
                                  headers=headers, params=params)

    def list(self, collection, path, retrieve_all=True, **params):
        if retrieve_all:
            res = []
            for r in self._pagination(collection, path, **params):
                res.extend(r[collection])
            return {collection: res}
        else:
            return self._pagination(collection, path, **params)

    def _pagination(self, collection, path, **params):
        if params.get('page_reverse', False):
            linkrel = 'previous'
        else:
            linkrel = 'next'
        next = True
        while next:
            res = self.get(path, params=params)
            yield res
            next = False
            try:
                for link in res['%s_links' % collection]:
                    if link['rel'] == linkrel:
                        query_str = urlparse.urlparse(link['href']).query
                        params = urlparse.parse_qs(query_str)
                        next = True
                        break
            except KeyError:
                break
