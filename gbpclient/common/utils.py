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
from neutronclient.common import utils as n_utils
import re


if not hasattr(n_utils, 'add_boolean_argument'):
    def add_boolean_argument(parser, name, **kwargs):
        for keyword in ('metavar', 'choices'):
            kwargs.pop(keyword, None)
        default = kwargs.pop('default', argparse.SUPPRESS)
        parser.add_argument(name, metavar='{True,False}',
                            choices=['True', 'true', 'False', 'false'],
                            default=default, **kwargs)
    n_utils.add_boolean_argument = add_boolean_argument


def str2dict(strdict):
    """Convert key1=value1,key2=value2,... string into dictionary.

    :param strdict: key1=value1,key2=value2
    Note: This implementation overrides the original implementation
    in the neutronclient such that it is no longer required to append
    the key with a = to specify a corresponding empty value. For example,
    key1=value1,key2,key3=value3
    key1
    key1,key2
    will also be supported and converted to a dictionary with empty
    values for the relevant keys.
    """
    if not strdict:
        return {}
    return dict([kv.split('=', 1) if '=' in kv else [kv, ""]
                 for kv in strdict.split(',')])


def str2list(strlist):
    """Convert key1,key2,... string into list.

    :param strlist: key1,key2
    strlist can be comma or space separated.
    """
    if strlist is not None:
        strlist = strlist.strip(', ')
    if not strlist:
        return []
    return re.split("[, ]+", strlist)
