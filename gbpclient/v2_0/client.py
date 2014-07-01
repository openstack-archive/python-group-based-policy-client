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
    """Client for the OpenStack Neutron v2.0 API.

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

    endpoints_path = "/grouppolicy/endpoints"
    endpoint_path = "/grouppolicy/endpoints/%s"
    endpoint_groups_path = "/grouppolicy/endpoint_groups"
    endpoint_group_path = "/grouppolicy/endpoint_groups/%s"
    l2_policies_path = "/grouppolicy/l2_policies"
    l2_policy_path = "/grouppolicy/l2_policies/%s"
    l3_policies_path = "/grouppolicy/l3_policies"
    l3_policy_path = "/grouppolicy/l3_policies/%s"
    policy_classifiers_path = "/grouppolicy/policy_classifiers"
    policy_classifier_path = "/grouppolicy/policy_classifiers/%s"
    policy_actions_path = "/grouppolicy/policy_actions"
    policy_action_path = "/grouppolicy/policy_actions/%s"
    policy_rules_path = "/grouppolicy/policy_rules"
    policy_rule_path = "/grouppolicy/policy_rules/%s"
    contracts_path = "/grouppolicy/contracts"
    contract_path = "/grouppolicy/contracts/%s"

    # API has no way to report plurals, so we have to hard code them
    EXTED_PLURALS = {'endpoints': 'endpoint',
                     'endpoint_groups': 'endpoint_group',
                     'l2_policies': 'l2_policy',
                     'l3_policies': 'l3_policy',
                     'policy_classifiers': 'policy_classifier',
                     'policy_actions': 'policy_action',
                     'policy_rules': 'policy_rule',
                     'contracts': 'contract',
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
    def list_endpoints(self, retrieve_all=True, **_params):
        """Fetches a list of all endpoints for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('endpoints', self.endpoints_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_endpoint(self, endpoint, **_params):
        """Fetches information of a certain endpoint."""
        return self.get(self.endpoint_path % (endpoint), params=_params)

    @APIParamsCall
    def create_endpoint(self, body=None):
        """Creates a new endpoint."""
        return self.post(self.endpoints_path, body=body)

    @APIParamsCall
    def update_endpoint(self, endpoint, body=None):
        """Updates a endpoint."""
        return self.put(self.endpoint_path % (endpoint), body=body)

    @APIParamsCall
    def delete_endpoint(self, endpoint):
        """Deletes the specified endpoint."""
        return self.delete(self.endpoint_path % (endpoint))

    @APIParamsCall
    def list_endpoint_groups(self, retrieve_all=True, **_params):
        """Fetches a list of all endpoint_groups for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('endpoint_groups', self.endpoint_groups_path,
                         retrieve_all, **_params)

    @APIParamsCall
    def show_endpoint_group(self, endpoint_group, **_params):
        """Fetches information of a certain endpoint_group."""
        return self.get(self.endpoint_group_path % (endpoint_group),
                        params=_params)

    @APIParamsCall
    def create_endpoint_group(self, body=None):
        """Creates a new endpoint_group."""
        return self.post(self.endpoint_groups_path, body=body)

    @APIParamsCall
    def update_endpoint_group(self, endpoint_group, body=None):
        """Updates a endpoint_group."""
        return self.put(self.endpoint_group_path % (endpoint_group),
                        body=body)

    @APIParamsCall
    def delete_endpoint_group(self, endpoint_group):
        """Deletes the specified endpoint_group."""
        return self.delete(self.endpoint_group_path % (endpoint_group))

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
    def list_contracts(self, retrieve_all=True, **_params):
        """Fetches a list of all contracts for a tenant."""
        # Pass filters in "params" argument to do_request
        return self.list('contracts', self.contracts_path, retrieve_all,
                         **_params)

    @APIParamsCall
    def show_contract(self, contract, **_params):
        """Fetches information of a certain contract."""
        return self.get(self.contract_path % (contract), params=_params)

    @APIParamsCall
    def create_contract(self, body=None):
        """Creates a new contract."""
        return self.post(self.contracts_path, body=body)

    @APIParamsCall
    def update_contract(self, contract, body=None):
        """Updates a contract."""
        return self.put(self.contract_path % (contract), body=body)

    @APIParamsCall
    def delete_contract(self, contract):
        """Deletes the specified contract."""
        return self.delete(self.contract_path % (contract))

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
