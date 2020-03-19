# Copyright 2020 Red Hat, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from functools import wraps

import testtools

from oslo_utils import excutils
from tempest import config
from tempest.lib import exceptions

CONF = config.CONF


def skip_if_not_implemented(f):
    """A decorator to raise a skip exception for not implemented features.

    This decorator raises a skipException if the method raises a
    NotImplemented exception. If "skip_if_not_implemented=False"
    argument was passed to the method, the NotImplemented exception will
    be raised.

    @param skip_if_not_implemented: If True (default), raise skipException.
    """
    @wraps(f)
    def wrapper(*func_args, **func_kwargs):

        skip = func_kwargs.pop('skip_if_not_implemented', True)
        if CONF.loadbalancer_feature_enabled.not_implemented_is_error:
            skip = False
        try:
            return f(*func_args, **func_kwargs)
        except exceptions.NotImplemented as e:
            with excutils.save_and_reraise_exception():
                if not skip:
                    raise
                message = ("The configured provider driver '{driver}' "
                           "does not support a feature required for this "
                           "test.".format(
                               driver=CONF.load_balancer.provider))
                if hasattr(e, 'resp_body'):
                    message = e.resp_body.get('faultstring', message)
                raise testtools.TestCase.skipException(message)
    return wrapper
