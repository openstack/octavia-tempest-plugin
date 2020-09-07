#   Copyright 2017 GoDaddy
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

import time

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const

CONF = config.CONF
LOG = logging.getLogger(__name__)


def wait_for_status(show_client, id, status_key, status,
                    check_interval, check_timeout, root_tag=None,
                    error_ok=False, **kwargs):
    """Waits for an object to reach a specific status.

    :param show_client: The tempest service client show method.
                        Ex. cls.os_primary.servers_client.show_server
    :param id: The id of the object to query.
    :param status_key: The key of the status field in the response.
                       Ex. provisioning_status
    :param status: The status to wait for. Ex. "ACTIVE"
    :check_interval: How often to check the status, in seconds.
    :check_timeout: The maximum time, in seconds, to check the status.
    :root_tag: The root tag on the response to remove, if any.
    :error_ok: When true, ERROR status will not raise an exception.
    :raises CommandFailed: Raised if the object goes into ERROR and ERROR was
                           not the desired status.
    :raises TimeoutException: The object did not achieve the status or ERROR in
                              the check_timeout period.
    :returns: The object details from the show client.
    """
    start = int(time.time())
    LOG.info('Waiting for {name} status to update to {status}'.format(
        name=show_client.__name__, status=status))
    while True:
        if status == const.DELETED:
            try:
                response = show_client(id, **kwargs)
            except exceptions.NotFound:
                return
        else:
            response = show_client(id, **kwargs)

        if root_tag:
            object_details = response[root_tag]
        else:
            object_details = response

        if object_details[status_key] == status:
            LOG.info('{name}\'s status updated to {status}.'.format(
                name=show_client.__name__, status=status))
            return object_details
        elif object_details[status_key] == 'ERROR' and not error_ok:
            message = ('{name} {field} updated to an invalid state of '
                       'ERROR'.format(name=show_client.__name__,
                                      field=status_key))
            caller = test_utils.find_test_caller()
            if caller:
                message = '({caller}) {message}'.format(caller=caller,
                                                        message=message)
            raise exceptions.UnexpectedResponseCode(message)

        if int(time.time()) - start >= check_timeout:
            message = (
                '{name} {field} failed to update to {expected_status} within '
                'the required time {timeout}. Current status of {name}: '
                '{status}'.format(
                    name=show_client.__name__,
                    timeout=check_timeout,
                    status=object_details[status_key],
                    expected_status=status,
                    field=status_key
                ))
            caller = test_utils.find_test_caller()
            if caller:
                message = '({caller}) {message}'.format(caller=caller,
                                                        message=message)
            raise exceptions.TimeoutException(message)

        time.sleep(check_interval)


def wait_for_not_found(delete_func, show_func, *args, **kwargs):
    """Call the delete function, then wait for it to be 'NotFound'

    :param delete_func: The delete function to call.
    :param show_func: The show function to call looking for 'NotFound'.
    :param ID: The ID of the object to delete/show.
    :raises TimeoutException: The object did not achieve the status or ERROR in
                              the check_timeout period.
    :returns: None
    """
    try:
        delete_func(*args, **kwargs)
    except exceptions.NotFound:
        return
    start = int(time.time())
    LOG.info('Waiting for object to be NotFound')
    while True:
        try:
            show_func(*args, **kwargs)
        except exceptions.NotFound:
            return
        if int(time.time()) - start >= CONF.load_balancer.check_timeout:
            message = ('{name} did not raise NotFound in {timeout} '
                       'seconds.'.format(
                           name=show_func.__name__,
                           timeout=CONF.load_balancer.check_timeout))
            raise exceptions.TimeoutException(message)
        time.sleep(CONF.load_balancer.check_interval)


def wait_for_deleted_status_or_not_found(
        show_client, id, status_key, check_interval, check_timeout,
        root_tag=None, **kwargs):
    """Waits for an object to reach a DELETED status or be not found (404).

    :param show_client: The tempest service client show method.
                        Ex. cls.os_primary.servers_client.show_server
    :param id: The id of the object to query.
    :param status_key: The key of the status field in the response.
                       Ex. provisioning_status
    :check_interval: How often to check the status, in seconds.
    :check_timeout: The maximum time, in seconds, to check the status.
    :root_tag: The root tag on the response to remove, if any.
    :raises CommandFailed: Raised if the object goes into ERROR and ERROR was
                           not the desired status.
    :raises TimeoutException: The object did not achieve the status or ERROR in
                              the check_timeout period.
    :returns: None
    """
    start = int(time.time())
    LOG.info('Waiting for {name} status to update to DELETED or be not '
             'found(404)'.format(name=show_client.__name__))
    while True:
        try:
            response = show_client(id, **kwargs)
        except exceptions.NotFound:
            return

        if root_tag:
            object_details = response[root_tag]
        else:
            object_details = response

        if object_details[status_key] == const.DELETED:
            LOG.info('{name}\'s status updated to DELETED.'.format(
                name=show_client.__name__))
            return
        elif int(time.time()) - start >= check_timeout:
            message = (
                '{name} {field} failed to update to DELETED or become not '
                'found (404) within the required time {timeout}. Current '
                'status of {name}: {status}'.format(
                    name=show_client.__name__,
                    timeout=check_timeout,
                    status=object_details[status_key],
                    field=status_key
                ))
            caller = test_utils.find_test_caller()
            if caller:
                message = '({caller}) {message}'.format(caller=caller,
                                                        message=message)
            raise exceptions.TimeoutException(message)

        time.sleep(check_interval)


def wait_for_spare_amps(list_func, check_interval, check_timeout):
    """Waits for amphorae in spare pool.

    :param list_func: The tempest service client amphora list method.
                        Ex. cls.os_admin.amphora_client.list_amphorae
    :check_interval: How often to check the status, in seconds.
    :check_timeout: The maximum time, in seconds, to check the status.
    :raises TimeoutException: No amphora available in spare pool in the
                              check_timeout period.
    :returns: A list of amphorae in spare pool.
    """

    LOG.info('Waiting for amphorae in spare pool')
    start = int(time.time())
    while True:
        spare_amps = list_func(
            query_params='{status}={status_ready}'.format(
                status=const.STATUS, status_ready=const.STATUS_READY))
        if len(spare_amps) >= 1:
            return spare_amps
        if int(time.time()) - start >= check_timeout:
            message = ("No available amphorae in spare pool within the "
                       "required time {timeout}.".format(
                           timeout=check_timeout))
            raise exceptions.TimeoutException(message)
        time.sleep(check_interval)


def wait_until_true(func, timeout=60, sleep=1, **kwargs):
    """Wait until callable predicate is evaluated as True

    :param func: Callable deciding whether waiting should continue.
    :param timeout: Timeout in seconds how long should function wait.
    :param sleep: Polling interval for results in seconds.
    """
    start = int(time.time())
    while True:
        try:
            ret = func(**kwargs)
            if ret:
                return
        except Exception as e:
            LOG.error(e)

        if int(time.time()) - start >= timeout:
            message = "Timed out after {timeout} seconds waiting".format(
                timeout=timeout)
            raise exceptions.TimeoutException(message)
        time.sleep(sleep)
