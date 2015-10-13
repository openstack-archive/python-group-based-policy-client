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

import testtools

from gbpclient.common import utils


class TestUtils(testtools.TestCase):
    def test_string_to_dictionary(self):
        input_str = 'key1'
        expected = {'key1': ''}
        self.assertEqual(expected, utils.str2dict(input_str))
        input_str = 'key1,key2'
        expected = {'key1': '', 'key2': ''}
        self.assertEqual(expected, utils.str2dict(input_str))
        input_str = 'key1=value1,key2'
        expected = {'key1': 'value1', 'key2': ''}
        self.assertEqual(expected, utils.str2dict(input_str))
        input_str = 'key1=value1,key2=value2'
        expected = {'key1': 'value1', 'key2': 'value2'}
        self.assertEqual(expected, utils.str2dict(input_str))

    def test_none_string_to_dictionary(self):
        input_str = ''
        expected = {}
        self.assertEqual(expected, utils.str2dict(input_str))
        input_str = None
        expected = {}
        self.assertEqual(expected, utils.str2dict(input_str))

    def test_string_to_list(self):
        input_str = 'key1'
        expected = ['key1']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = 'key1, key2'
        expected = ['key1', 'key2']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = 'key1,key2'
        expected = ['key1', 'key2']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = 'key1,key2,'
        expected = ['key1', 'key2']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = 'key1,key2,'
        expected = ['key1', 'key2']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = ',key1,key2 '
        expected = ['key1', 'key2']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = 'key1 key2'
        expected = ['key1', 'key2']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = ' key1 key2 '
        expected = ['key1', 'key2']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = 'key1 key2, key3 '
        expected = ['key1', 'key2', 'key3']
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = ' , key1 key2, , key3 '
        expected = ['key1', 'key2', 'key3']
        self.assertEqual(expected, utils.str2list(input_str))

    def test_none_string_to_list(self):
        input_str = ''
        expected = []
        self.assertEqual(expected, utils.str2list(input_str))
        input_str = None
        expected = []
        self.assertEqual(expected, utils.str2list(input_str))
