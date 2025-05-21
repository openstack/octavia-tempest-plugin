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


def retry_on_port_in_use(start_port, max_retries=3):
    """Decorator to retry a test function if the specified port is in use.

    This handles cases where a test fails due to a port conflict, typically
    caused by another service binding the same port on the host. The decorator
    catches '[Errno 98] Address already in use' errors and retries the test
    using incrementally higher port numbers.

    The decorated function must accept `port` as its first parameter.

    :param start_port: Initial port to attempt.
    :param max_retries: Number of retries with incremented port values.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            port = start_port
            last_exception = None

            for _ in range(max_retries):
                try:
                    return func(self, port, *args, **kwargs)
                except exceptions.NotImplemented as e:
                    message = (
                        "The configured provider driver '{driver}' does not "
                        "support a feature required for this test.".format(
                            driver=CONF.load_balancer.provider
                        )
                    )
                    if hasattr(e, 'resp_body'):
                        message = e.resp_body.get('faultstring', message)
                    raise testtools.TestCase.skipException(message)

                except Exception as e:
                    if "Address already in use" in str(e):
                        last_exception = e
                        port += 1
                    else:
                        raise

            raise Exception(f"All port attempts failed after {max_retries} "
                            f"retries. Last error: {last_exception}")
        return wrapper
    return decorator
