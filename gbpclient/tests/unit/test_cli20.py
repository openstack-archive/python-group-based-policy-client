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

from mox3 import mox
from neutronclient.common import exceptions
from neutronclient.tests.unit import test_cli20 as neutron_test_cli20
import requests

from gbpclient import gbpshell
from gbpclient.v2_0 import client as gbpclient

API_VERSION = neutron_test_cli20.API_VERSION
FORMAT = neutron_test_cli20.FORMAT
TOKEN = neutron_test_cli20.TOKEN
ENDURL = neutron_test_cli20.ENDURL
capture_std_streams = neutron_test_cli20.capture_std_streams
end_url = neutron_test_cli20.end_url


class FakeStdout(neutron_test_cli20.FakeStdout):

    pass


class MyResp(neutron_test_cli20.MyResp):

    pass


class MyApp(neutron_test_cli20.MyApp):

    pass


class MyUrlComparator(neutron_test_cli20.MyUrlComparator):

    pass


class MyComparator(neutron_test_cli20.MyComparator):

    pass


class CLITestV20Base(neutron_test_cli20.CLITestV20Base):

    shell = gbpshell
    client = gbpclient


class ClientV2TestJson(CLITestV20Base):

    pass


class CLITestV20ExceptionHandler(CLITestV20Base):

    def _test_exception_handler_v20(
        self, expected_exception, status_code, expected_msg,
        error_type=None, error_msg=None, error_detail=None,
        error_content=None):
        if error_content is None:
            error_content = {'NeutronError': {'type': error_type,
                                              'message': error_msg,
                                              'detail': error_detail}}

        e = self.assertRaises(expected_exception,
                              gbpclient.exception_handler_v20,
                              status_code, error_content)
        self.assertEqual(status_code, e.status_code)

        if expected_msg is None:
            if error_detail:
                expected_msg = '\n'.join([error_msg, error_detail])
            else:
                expected_msg = error_msg
        self.assertEqual(expected_msg, e.message)

    def test_exception_handler_v20_neutron_known_error(self):
        # TODO(Sumit): This needs to be adapted for GBP
        pass

    def test_exception_handler_v20_neutron_known_error_without_detail(self):
        # TODO(Sumit): This needs to be adapted for GBP
        pass

    def test_exception_handler_v20_unknown_error_to_per_code_exception(self):
        for status_code, client_exc in exceptions.HTTP_EXCEPTION_MAP.items():
            error_msg = 'Unknown error'
            error_detail = 'This is detail'
            self._test_exception_handler_v20(
                client_exc, status_code,
                error_msg + '\n' + error_detail,
                'UnknownError', error_msg, error_detail)

    def test_exception_handler_v20_neutron_unknown_status_code(self):
        error_msg = 'Unknown error'
        error_detail = 'This is detail'
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 501,
            error_msg + '\n' + error_detail,
            'UnknownError', error_msg, error_detail)

    def test_exception_handler_v20_bad_neutron_error(self):
        error_content = {'NeutronError': {'unknown_key': 'UNKNOWN'}}
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg={'unknown_key': 'UNKNOWN'},
            error_content=error_content)

    def test_exception_handler_v20_error_dict_contains_message(self):
        error_content = {'message': 'This is an error message'}
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg='This is an error message',
            error_content=error_content)

    def test_exception_handler_v20_error_dict_not_contain_message(self):
        error_content = {'error': 'This is an error message'}
        expected_msg = '%s-%s' % (500, error_content)
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg=expected_msg,
            error_content=error_content)

    def test_exception_handler_v20_default_fallback(self):
        error_content = 'This is an error message'
        expected_msg = '%s-%s' % (500, error_content)
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg=expected_msg,
            error_content=error_content)

    def test_exception_status(self):
        e = exceptions.BadRequest()
        self.assertEqual(e.status_code, 400)

        e = exceptions.BadRequest(status_code=499)
        self.assertEqual(e.status_code, 499)

        # SslCertificateValidationError has no explicit status_code,
        # but should have a 'safe' defined fallback.
        e = exceptions.SslCertificateValidationError()
        self.assertIsNotNone(e.status_code)

        e = exceptions.SslCertificateValidationError(status_code=599)
        self.assertEqual(e.status_code, 599)

    def test_connection_failed(self):
        self.mox.StubOutWithMock(self.client.httpclient, 'request')
        self.client.httpclient.auth_token = 'token'

        self.client.httpclient.request(
            end_url('/test'), 'GET',
            headers=mox.ContainsKeyValue('X-Auth-Token', 'token')
        ).AndRaise(requests.exceptions.ConnectionError('Connection refused'))

        self.mox.ReplayAll()

        error = self.assertRaises(exceptions.ConnectionFailed,
                                  self.client.get, '/test')
        # NB: ConnectionFailed has no explicit status_code, so this
        # tests that there is a fallback defined.
        self.assertIsNotNone(error.status_code)
        self.mox.VerifyAll()
        self.mox.UnsetStubs()
