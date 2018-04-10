# Copyright 2017 GoDaddy
# Copyright 2017 Catalyst IT Ltd
# Copyright 2018 Rackspace US Inc.  All rights reserved.
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

import requests
import time

from oslo_log import log as logging
from tempest import config
from tempest.lib import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


def validate_URL_response(URL, expected_status_code=200,
                          expected_body=None, HTTPS_verify=True,
                          client_cert_path=None, CA_certs_path=None,
                          request_interval=CONF.load_balancer.build_interval,
                          request_timeout=CONF.load_balancer.build_timeout):
    """Check a URL response (HTTP or HTTPS).

    :param URL: The URL to query.
    :param expected_status_code: The expected HTTP status code.
    :param expected_body: The expected response text, None will not compare.
    :param HTTPS_verify: Should we verify the HTTPS server.
    :param client_cert_path: Filesystem path to a file with the client private
                             key and certificate.
    :param CA_certs_path: Filesystem path to a file containing CA certificates
                          to use for HTTPS validation.
    :param request_interval: Time, in seconds, to timeout a request.
    :param request_timeout: The maximum time, in seconds, to attempt requests.
                            Failed validation of expected results does not
                            result in a retry.
    :raises InvalidHttpSuccessCode: The expected_status_code did not match.
    :raises InvalidHTTPResponseBody: The response body did not match the
                                     expected content.
    :raises TimeoutException: The request timed out.
    :returns: None
    """
    with requests.Session() as session:
        session_kwargs = {}
        if not HTTPS_verify:
            session_kwargs['verify'] = False
        if CA_certs_path:
            session_kwargs['verify'] = CA_certs_path
        if client_cert_path:
            session_kwargs['cert'] = client_cert_path
        session_kwargs['timeout'] = request_interval
        start = time.time()
        while time.time() - start < request_timeout:
            try:
                response = session.get(URL, **session_kwargs)
                if response.status_code != expected_status_code:
                    raise exceptions.InvalidHttpSuccessCode(
                        '{0} is not the expected code {1}'.format(
                            response.status_code, expected_status_code))
                if expected_body and response.text != expected_body:
                    details = '{} does not match expected {}'.format(
                        response.text, expected_body)
                    raise exceptions.InvalidHTTPResponseBody(
                        resp_body=details)
                return
            except requests.exceptions.Timeout:
                # Don't sleep as we have already waited the interval.
                LOG.info('Request for () timed out. Retrying.'.format(URL))
            except (exceptions.InvalidHttpSuccessCode,
                    exceptions.InvalidHTTPResponseBody,
                    requests.exceptions.SSLError):
                raise
            except Exception as e:
                LOG.info('Validate URL got exception: {0}. '
                         'Retrying.'.format(e))
                time.sleep(request_interval)
        raise exceptions.TimeoutException()
