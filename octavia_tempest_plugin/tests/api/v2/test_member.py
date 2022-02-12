# Copyright 2018 GoDaddy
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

import testtools
import time
from uuid import UUID

from dateutil import parser
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import misc
from tempest.lib import decorators
from tempest.lib import exceptions

from octavia_tempest_plugin.common import constants as const
from octavia_tempest_plugin.tests import test_base
from octavia_tempest_plugin.tests import waiters

CONF = config.CONF

# Member port numbers need to be unique on the shared pools so generate them
@misc.singleton
class MemberPort(object):

    current_port = 8000

    def increment(self):
        self.current_port += 1
        return self.current_port


class MemberAPITest(test_base.LoadBalancerBaseTest):
    """Test the member object API."""

    @classmethod
    def resource_setup(cls):
        """Setup resources needed by the tests."""
        super(MemberAPITest, cls).resource_setup()

        lb_name = data_utils.rand_name("lb_member_lb1_member")
        lb_kwargs = {const.PROVIDER: CONF.load_balancer.provider,
                     const.NAME: lb_name}
        cls._setup_lb_network_kwargs(lb_kwargs)

        cls.current_listener_port = 8000
        cls.listener_pool_cache = {}
        cls.member_port = MemberPort()

        lb = cls.mem_lb_client.create_loadbalancer(**lb_kwargs)
        cls.lb_id = lb[const.ID]
        cls.addClassResourceCleanup(
            cls.mem_lb_client.cleanup_loadbalancer,
            cls.lb_id, cascade=True)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.lb_build_interval,
                                CONF.load_balancer.lb_build_timeout)

    @classmethod
    def _listener_pool_create(cls, listener_protocol, pool_protocol,
                              algorithm):
        """Setup resources needed by the tests."""
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            cls.mem_listener_client.is_version_supported(
                cls.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')

        if (listener_protocol == const.UDP and
                not cls.mem_listener_client.is_version_supported(
                    cls.api_version, '2.1')):
            raise cls.skipException('UDP listener support is only available '
                                    'in Octavia API version 2.1 or newer')

        # Cache listener/pool combinations we have already created as
        # they can be reused for member test permutations
        listener_pool_key = listener_protocol + pool_protocol + algorithm
        pool_id = cls.listener_pool_cache.get(listener_pool_key, None)
        if pool_id is not None:
            return pool_id

        listener_name = data_utils.rand_name("lb_member_listener1_member")
        listener_kwargs = {
            const.NAME: listener_name,
            const.PROTOCOL: listener_protocol,
            const.PROTOCOL_PORT: cls.current_listener_port,
            const.LOADBALANCER_ID: cls.lb_id,
            const.CONNECTION_LIMIT: 200
        }
        cls.current_listener_port += 1
        listener = cls.mem_listener_client.create_listener(**listener_kwargs)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        pool_name = data_utils.rand_name("lb_member_pool1_member")
        pool_kwargs = {
            const.NAME: pool_name,
            const.PROTOCOL: pool_protocol,
            const.LB_ALGORITHM: algorithm,
            const.LISTENER_ID: listener[const.ID]
        }

        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = cls.mem_pool_client.create_pool(**pool_kwargs)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        waiters.wait_for_status(cls.mem_lb_client.show_loadbalancer,
                                cls.lb_id, const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)
        cls.listener_pool_cache[listener_pool_key] = pool[const.ID]
        return pool[const.ID]


class MemberAPITest1(MemberAPITest):
    @decorators.idempotent_id('0684575a-0970-4fa8-8006-10c2b39c5f2b')
    def test_ipv4_HTTP_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('10641ec2-981e-4092-a0d0-89a434506eef')
    def test_ipv4_HTTP_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('dce70b40-502b-4b1c-8592-180817324ea0')
    def test_ipv4_HTTPS_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('46555ea6-12a8-4961-b105-bffdead7abcd')
    def test_ipv4_HTTPS_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('c1a5e297-f38e-4fc8-92a4-4177a37c4794')
    def test_ipv4_PROXY_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('dfe24159-96a4-4496-888e-e74acd9d390d')
    def test_ipv4_PROXY_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('2716d05d-6b04-405e-bda9-e79c778eb6dd')
    def test_ipv4_TCP_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('14ee6e7d-c434-4e2e-947b-1a37d5ffa3bd')
    def test_ipv4_TCP_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('fb9d0708-e320-45d7-be30-f6e7ea45c644')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('5d36d4a4-3b9c-4d54-af61-5f80080bb040')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('0623aa1f-753d-44e7-afa1-017d274eace7')
    def test_ipv4_HTTP_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('96b709fa-dca3-4780-8de7-fb168d455d76')
    def test_ipv4_HTTP_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('5354ac6c-653d-43ce-8096-1f9de961de73')
    def test_ipv4_HTTPS_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('e5c8503a-4bc5-43ad-b0da-3e5c1ef719f7')
    def test_ipv4_HTTPS_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('b2c8632b-f833-4844-9af3-ffee655be6bf')
    def test_ipv4_PROXY_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('e565de98-88e2-4529-9730-a66073e31480')
    def test_ipv4_PROXY_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('9306b599-c8e2-4ce9-b789-9e32d42406c4')
    def test_ipv4_TCP_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('9bbfec96-a7e5-414d-96d1-710e468b8700')
    def test_ipv4_TCP_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('ccced84a-994d-4d30-a07a-30fa83e4dde2')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('bc0802dd-633f-42d4-8c6a-b4c70af29870')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('0d9a8b32-0c13-49ea-8dd3-a124ec4ac6f9')
    def test_ipv4_HTTP_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('57c52d0c-0a62-4988-a02e-2f9f8b440d08')
    def test_ipv4_HTTP_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('df427d31-9843-4840-9137-6b88c633d329')
    def test_ipv4_HTTPS_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('e64c28f6-09f5-4fd8-a59e-bcf90975581a')
    def test_ipv4_HTTPS_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('5c32e2fd-9148-466c-b788-e11d7a48483b')
    def test_ipv4_PROXY_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('76435fb2-dcb3-4be2-ada9-2dbc375c100b')
    def test_ipv4_PROXY_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('62db0223-1e44-4d6c-8499-9f72c86d30e3')
    def test_ipv4_TCP_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('2da54523-cefc-4a44-ab07-c33ffe891bf0')
    def test_ipv4_TCP_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('9a298318-89a5-416f-b027-af5eda94f813')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('b0455c5e-3702-41d7-8069-6ce55563767c')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('a2dbf216-a974-45e1-822d-859f76c89ed6')
    def test_ipv4_HTTP_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('926eeed9-ecf4-4d22-9417-ef7a7e0a7788')
    def test_ipv4_HTTP_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('55da07bc-bf2c-4924-aba3-a03456843e14')
    def test_ipv4_HTTPS_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('6773a8bd-1c51-4040-84ba-1aa2b6c4280d')
    def test_ipv4_HTTPS_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('ab462d7c-069d-4b55-b6a7-dd199bde65b3')
    def test_ipv4_PROXY_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('b1f6f779-2535-4e47-add2-24561545ba59')
    def test_ipv4_PROXY_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('73673efc-5b70-4394-b831-1d59fe283e7d')
    def test_ipv4_TCP_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('0a08da1e-84f5-4068-84ec-1312b6b8bee3')
    def test_ipv4_TCP_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('caf68a97-1911-466c-b392-50b946e2395c')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('bb750dc5-73a8-4722-bf3b-cdafaefe7914')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_ipv4_UDP_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(4, pool_id)

    @decorators.idempotent_id('cd894c4f-2256-405f-aa6e-2f77973c749a')
    def test_ipv6_HTTP_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('3bbb8554-f757-4673-92e3-8593eef83f19')
    def test_ipv6_HTTP_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('6056724b-d046-497a-ae31-c02af67d4fbb')
    def test_ipv6_HTTPS_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('354e44d3-db08-4ba9-8e3e-8c3210542a86')
    def test_ipv6_HTTPS_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('0f8b924e-dd0b-44f9-92b6-8f3dfb0a720c')
    def test_ipv6_PROXY_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('d1efbfab-b674-4b78-8014-7ecf7ab464ac')
    def test_ipv6_PROXY_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('699f1c0d-65ae-40d7-9abd-2cef0a1560b9')
    def test_ipv6_TCP_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('595255f9-f595-43e7-a398-80dd76719aa8')
    def test_ipv6_TCP_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('0c2c2d5f-9602-4602-82e7-94a1393c295d')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_LC_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('d41f5b46-ba06-42bf-a320-0fda106a7543')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_LC_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('141944cc-5e2c-4e83-88f8-f61a6797c9b7')
    def test_ipv6_HTTP_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('883db951-adb1-4e05-8369-99f38fde6b3c')
    def test_ipv6_HTTP_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('364ba4b9-825a-4f92-9bf2-8d76bcba0288')
    def test_ipv6_HTTPS_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('70ba1deb-d644-437f-af80-4299461b20af')
    def test_ipv6_HTTPS_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('06facdb2-5b7e-4e8b-810d-8f829c619a6d')
    def test_ipv6_PROXY_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('4ec5a74b-06bd-4005-8fcc-25d1bced4807')
    def test_ipv6_PROXY_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('22600457-ffe5-44a0-90b0-da4f48051023')
    def test_ipv6_TCP_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('57e6f861-5a55-43a5-9cae-a966bd2a48eb')
    def test_ipv6_TCP_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('4cddcf8a-566e-4a5a-bf81-99026b17f676')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_RR_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('26547c9a-6bbc-429a-9436-e94f2930b9e1')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_RR_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('6759674b-dca0-4a48-b166-3f87dc1cc727')
    def test_ipv6_HTTP_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('683d9ef4-6af3-48e2-aba4-9f404d493467')
    def test_ipv6_HTTP_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('3d308996-3522-4c91-9bfd-48fedc2ed2f2')
    def test_ipv6_HTTPS_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('dc26ce07-d580-4a55-b7cd-1b4f09c13572')
    def test_ipv6_HTTPS_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('56944f91-bf4b-4e9a-9b05-6207e8184c75')
    def test_ipv6_PROXY_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('e8f4eb38-8e8b-485a-b70a-b1679ad58b66')
    def test_ipv6_PROXY_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('fc0e77b1-e115-4ec7-80e3-c00d79932549')
    def test_ipv6_TCP_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('66ddafd2-ace3-43ea-b78b-78b6b0a4d9eb')
    def test_ipv6_TCP_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('ccfc1283-9e8e-4aa5-a5d3-1d18d57bec65')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_SI_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('b62c8562-fdbb-4989-a5ae-d9e1c1b76cd5')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_SI_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('d816d324-2434-4812-9b3e-a3f0d4949008')
    def test_ipv6_HTTP_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('d4cfe315-b6d6-4940-8ff6-5f5252028eec')
    def test_ipv6_HTTP_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('05684ab0-dff3-41aa-8b42-7f95fd6aa4ab')
    def test_ipv6_HTTPS_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('ed42872c-1ffc-4210-9f69-5f7eb8ec732f')
    def test_ipv6_HTTPS_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('ab87132f-5a0e-40a1-9498-9883780d31a9')
    def test_ipv6_PROXY_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('227d7f40-a224-4e67-8844-2d28abc5171e')
    def test_ipv6_PROXY_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('b8394de8-a898-4cab-aa0c-f3168d702ee0')
    def test_ipv6_TCP_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('7a86e00b-90bf-4fd3-8636-ae7264929106')
    def test_ipv6_TCP_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id)

    @decorators.idempotent_id('5abdfbcd-d1cd-4e6a-b98f-79afea442ad8')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_SIP_alt_monitor_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id, alternate_monitor=True)

    @decorators.idempotent_id('63f558b4-d2f8-4e4c-828b-3651e50844b7')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   not CONF.load_balancer.test_with_ipv6))
    def test_ipv6_UDP_SIP_member_create(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_create(6, pool_id)

    def _test_member_create(self, ip_version, pool_id,
                            alternate_monitor=False):
        """Tests member create and basic show APIs.

        * Tests that users without the loadbalancer member role cannot
          create members.
        * Create a fully populated member.
        * If driver doesnt support Monitors, allow to create without monitor
        * Show member details.
        * Validate the show reflects the requested values.
        """
        if ip_version == 6 and not CONF.load_balancer.test_with_ipv6:
            raise testtools.TestCase.skipException(
                'Skipping this test as test_with_ipv6 is not "True" in '
                'the tempest.conf [load_balancer] section. Testing with '
                'IPv6 is disabled. :-(')

        if ip_version == 4:
            member_address = '192.0.2.1'
            member_monitor_address = '192.0.2.2'
        else:
            member_address = '2001:db8:0:0:0:0:0:1'
            member_monitor_address = '2001:db8:0:0:0:0:0:2'

        member_name = data_utils.rand_name("lb_member_member1-create")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: pool_id,
            const.ADDRESS: member_address,
            const.PROTOCOL_PORT: self.member_port.increment(),
            const.WEIGHT: 50,
        }

        if alternate_monitor:
            member_kwargs[const.MONITOR_ADDRESS] = member_monitor_address
            member_kwargs[const.MONITOR_PORT] = 8080

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_kwargs.update({
                const.BACKUP: False,
            })

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            member_tags = ["hello", "world"]
            member_kwargs.update({
                const.TAGS: member_tags
            })

        if self.lb_member_vip_subnet:
            member_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        # Test that a user without the load balancer role cannot
        # create a member
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            member_client = self.os_primary.load_balancer_v2.MemberClient()
            self.assertRaises(
                exceptions.Forbidden,
                member_client.create_member,
                **member_kwargs)

        # Test that a user without the loadbalancer role cannot
        # create a member.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_create_RBAC_enforcement(
                'MemberClient', 'create_member',
                expected_allowed,
                status_method=self.mem_lb_client.show_loadbalancer,
                obj_id=self.lb_id, **member_kwargs)

        member = self.mem_member_client.create_member(**member_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)

        parser.parse(member[const.CREATED_AT])
        parser.parse(member[const.UPDATED_AT])
        UUID(member[const.ID])
        self.assertEqual(const.NO_MONITOR, member[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(member_kwargs[const.TAGS],
                                  member[const.TAGS])

        if alternate_monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]

        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

    @decorators.idempotent_id('fcc5c6cd-d1c2-4a49-8d26-2268608e59a6')
    def test_HTTP_LC_member_list(self):
        self._test_member_list(const.HTTP,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('33450ca2-db09-451a-bd46-6f260bf520f5')
    def test_HTTPS_LC_member_list(self):
        self._test_member_list(const.HTTPS,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('c17241d4-5cff-41e2-9742-047647d61546')
    def test_PROXY_LC_member_list(self):
        self._test_member_list(const.PROXY,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('d1300e9a-64ba-4d02-baf6-2523439b80d7')
    def test_TCP_LC_member_list(self):
        self._test_member_list(const.TCP,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('dffc1dfb-7506-4f81-b1e5-5835b9690079')
    def test_UDP_LC_member_list(self):
        self._test_member_list(const.UDP,
                               const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('9ce7ad78-915b-42ce-b0d8-44d88a929f3d')
    def test_HTTP_RR_member_list(self):
        self._test_member_list(const.HTTP,
                               const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('8f6362a1-d98b-4696-b88d-41e1eb4a9f70')
    def test_HTTPS_RR_member_list(self):
        self._test_member_list(const.HTTPS,
                               const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('ce4109f8-3bad-4965-95ec-7170519e4a3f')
    def test_PROXY_RR_member_list(self):
        self._test_member_list(const.PROXY,
                               const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('5c35df5d-8951-4506-905b-502f623cc9e4')
    def test_TCP_RR_member_list(self):
        self._test_member_list(const.TCP,
                               const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('c7de7d31-2910-4864-84df-61a883e916fb')
    def test_UDP_RR_member_list(self):
        self._test_member_list(const.UDP,
                               const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('0d142f26-c9e4-45bf-8cd7-1f5659301047')
    def test_HTTP_SI_member_list(self):
        self._test_member_list(const.HTTP,
                               const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('a2be8c21-c7b1-4c1d-ab39-43042bf75a19')
    def test_HTTPS_SI_member_list(self):
        self._test_member_list(const.HTTPS,
                               const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('1ab3978b-8a37-45d3-8e2c-aab4c2187d43')
    def test_PROXY_SI_member_list(self):
        self._test_member_list(const.PROXY,
                               const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('2da08931-bc4c-4339-b16a-43d40ca7734d')
    def test_TCP_SI_member_list(self):
        self._test_member_list(const.TCP,
                               const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('ea12a6bc-6267-4790-b2b3-cbd6a146533b')
    def test_UDP_SI_member_list(self):
        self._test_member_list(const.UDP,
                               const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('2f9d0974-2e55-49c1-b83a-8bdd6dfdb46c')
    def test_HTTP_SIP_member_list(self):
        self._test_member_list(const.HTTP,
                               const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('d31c5b8b-7ec1-4e78-a821-30e9a1e05139')
    def test_HTTPS_SIP_member_list(self):
        self._test_member_list(const.HTTPS,
                               const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('15f8690b-f345-413c-9b4e-af39d546fbec')
    def test_PROXY_SIP_member_list(self):
        self._test_member_list(const.PROXY,
                               const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('db5769ce-f4b0-4a0f-92a7-4eeed66b6730')
    def test_TCP_SIP_member_list(self):
        self._test_member_list(const.TCP,
                               const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('638811fa-26ce-44f3-8ac7-29cf1ef41838')
    def test_UDP_SIP_member_list(self):
        self._test_member_list(const.UDP,
                               const.LB_ALGORITHM_SOURCE_IP_PORT)

    def _test_member_list(self, pool_protocol, algorithm):
        """Tests member list API and field filtering.

        * Create a clean pool.
        * Create three members.
        * Validates that other accounts cannot list the members.
        * List the members using the default sort order.
        * List the members using descending sort order.
        * List the members using ascending sort order.
        * List the members returning one field at a time.
        * List the members returning two fields.
        * List the members filtering to one of the three.
        * List the members filtered, one field, and sorted.
        """
        # IDs of members created in the test
        test_ids = []

        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')
        if (pool_protocol == const.UDP and
                not self.mem_listener_client.is_version_supported(
                    self.api_version, '2.1')):
            raise self.skipException('UDP support is only available '
                                     'in Octavia API version 2.1 or newer')

        pool_name = data_utils.rand_name("lb_member_pool2_member-list")
        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(
                name=pool_name, loadbalancer_id=self.lb_id,
                protocol=pool_protocol,
                lb_algorithm=algorithm)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        pool_id = pool[const.ID]
        self.addCleanup(
            self.mem_pool_client.cleanup_pool, pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member1_name = data_utils.rand_name("lb_member_member2-list")
        member1_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 101,
        }

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            member1_tags = ["English", "Mathematics",
                            "Marketing", "Creativity"]
            member1_kwargs.update({const.TAGS: member1_tags})

        member1 = self.mem_member_client.create_member(
            **member1_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member1[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        member1 = waiters.wait_for_status(
            self.mem_member_client.show_member, member1[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        test_ids.append(member1[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        member2_name = data_utils.rand_name("lb_member_member1-list")
        member2_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 100,
        }

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            member2_tags = ["English", "Spanish",
                            "Soft_skills", "Creativity"]
            member2_kwargs.update({const.TAGS: member2_tags})

        member2 = self.mem_member_client.create_member(
            **member2_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member2[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        member2 = waiters.wait_for_status(
            self.mem_member_client.show_member, member2[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        test_ids.append(member2[const.ID])
        # Time resolution for created_at is only to the second, and we need to
        # ensure that each object has a distinct creation time. Delaying one
        # second is both a simple and a reliable way to accomplish this.
        time.sleep(1)

        member3_name = data_utils.rand_name("lb_member_member3-list")
        member3_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member3_name,
            const.ADMIN_STATE_UP: False,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 102,
        }

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            member3_tags = ["English", "Project_management",
                            "Communication", "Creativity"]
            member3_kwargs.update({const.TAGS: member3_tags})

        member3 = self.mem_member_client.create_member(
            **member3_kwargs)
        self.addCleanup(
            self.mem_member_client.cleanup_member,
            member3[const.ID], pool_id=pool_id,
            lb_client=self.mem_lb_client, lb_id=self.lb_id)
        member3 = waiters.wait_for_status(
            self.mem_member_client.show_member, member3[const.ID],
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.check_interval,
                                CONF.load_balancer.check_timeout)
        test_ids.append(member3[const.ID])

        # Test credentials that should see these members can see them.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin', 'os_roles_lb_member',
                                'os_roles_lb_global_observer']
        if expected_allowed:
            self.check_list_IDs_RBAC_enforcement(
                'MemberClient', 'list_members', expected_allowed,
                test_ids, pool_id)

        # Test that users without the lb member role cannot list members
        # Note: The parent pool ID blocks non-owners from listing members.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        # Note: os_admin is here because it evaluaties to "project_admin"
        #       in oslo_policy and since keystone considers "project_admin"
        #       a superscope of "project_reader". This means it can read
        #       objects in the "admin" credential's project.
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_admin', 'os_system_admin',
                                'os_system_reader', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_list_RBAC_enforcement(
                'MemberClient', 'list_members', expected_allowed, pool_id)

        # Check the default sort order, created_at
        members = self.mem_member_client.list_members(pool_id)
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member3[const.PROTOCOL_PORT],
                         members[2][const.PROTOCOL_PORT])

        # Test sort descending by protocol_port
        members = self.mem_member_client.list_members(
            pool_id, query_params='{sort}={descr}:{desc}'.format(
                sort=const.SORT, descr=const.PROTOCOL_PORT, desc=const.DESC))
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[2][const.PROTOCOL_PORT])
        self.assertEqual(member3[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])

        # Test sort ascending by protocol_port
        members = self.mem_member_client.list_members(
            pool_id, query_params='{sort}={descr}:{asc}'.format(
                sort=const.SORT, descr=const.PROTOCOL_PORT, asc=const.ASC))
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])
        self.assertEqual(member3[const.PROTOCOL_PORT],
                         members[2][const.PROTOCOL_PORT])

        # Test fields
        show_member_response_fields = const.SHOW_MEMBER_RESPONSE_FIELDS
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            show_member_response_fields.append('backup')
        for field in show_member_response_fields:
            members = self.mem_member_client.list_members(
                pool_id, query_params='{fields}={field}'.format(
                    fields=const.FIELDS, field=field))
            self.assertEqual(1, len(members[0]))
            self.assertEqual(member1[field], members[0][field])
            self.assertEqual(member2[field], members[1][field])
            self.assertEqual(member3[field], members[2][field])

        # Test multiple fields at the same time
        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{fields}={admin}&{fields}={created}'.format(
                fields=const.FIELDS, admin=const.ADMIN_STATE_UP,
                created=const.CREATED_AT))
        self.assertEqual(2, len(members[0]))
        self.assertTrue(members[0][const.ADMIN_STATE_UP])
        parser.parse(members[0][const.CREATED_AT])
        self.assertTrue(members[1][const.ADMIN_STATE_UP])
        parser.parse(members[1][const.CREATED_AT])
        self.assertFalse(members[2][const.ADMIN_STATE_UP])
        parser.parse(members[2][const.CREATED_AT])

        # Test filtering
        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{desc}={lb_desc}'.format(
                desc=const.PROTOCOL_PORT,
                lb_desc=member2[const.PROTOCOL_PORT]))
        self.assertEqual(1, len(members))
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])

        # Test combined params
        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{admin}={true}&'
                         '{fields}={descr}&{fields}={id}&'
                         '{sort}={descr}:{desc}'.format(
                             admin=const.ADMIN_STATE_UP,
                             true=const.ADMIN_STATE_UP_TRUE,
                             fields=const.FIELDS, descr=const.PROTOCOL_PORT,
                             id=const.ID, sort=const.SORT, desc=const.DESC))
        # Should get two members
        self.assertEqual(2, len(members))
        # members should have two fields
        self.assertEqual(2, len(members[0]))
        # Should be in descending order
        self.assertEqual(member2[const.PROTOCOL_PORT],
                         members[1][const.PROTOCOL_PORT])
        self.assertEqual(member1[const.PROTOCOL_PORT],
                         members[0][const.PROTOCOL_PORT])

        # Creating a list of 3 members, each one contains different tags
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            list_of_members = [member1, member2, member3]
            test_list = []
            for member in list_of_members:

                # If tags "English" and "Creativity" are in the member's tags
                # and "Spanish" is not, add the member to the list
                if "English" in member[const.TAGS] and "Creativity" in (
                    member[const.TAGS]) and "Spanish" not in (
                        member[const.TAGS]):
                    test_list.append(member[const.NAME])

            # Tests if only the first and the third ones have those tags
            self.assertEqual(
                test_list, [member1[const.NAME], member3[const.NAME]])

            # Tests that filtering by an empty tag will return an empty list
            self.assertTrue(not any(["" in member[const.TAGS]
                                     for member in list_of_members]))


class MemberAPITest2(MemberAPITest):
    @decorators.idempotent_id('2674b363-7922-494a-b121-cf415dbbb716')
    def test_HTTP_LC_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('a99da0e8-0595-49a5-a788-efc37fad2dc2')
    def test_HTTP_LC_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('c3db94b3-a38c-4a0a-8c53-85888c2e1876')
    def test_HTTPS_LC_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('5844580e-6d01-42dc-b951-d995c9612167')
    def test_HTTPS_LC_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('ebc52abf-9133-4922-902c-505f890bb44e')
    def test_PROXY_LC_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('43f90043-65d4-483a-99ab-564f25acc0d7')
    def test_PROXY_LC_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('ecec1c11-2c2c-408c-9b4e-01620266dab6')
    def test_TCP_LC_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('baa9b4ec-1ac5-431f-bae0-f2ef68d1c81a')
    def test_TCP_LC_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('3a291344-0a88-46fc-9eca-c2c6b9048076')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_LC_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('e53b2d6a-ad3f-46be-b899-56324874ad24')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_LC_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('7674ae04-7e92-44ef-9adf-40718d7ec705')
    def test_HTTP_RR_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('2c4a29f4-be25-416c-9546-9585298cfe4c')
    def test_HTTP_RR_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('a06a137d-f6d1-44a6-978b-22fe8e23752c')
    def test_HTTPS_RR_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('bfe7dfea-878e-4e7c-afd8-9860d7282930')
    def test_HTTPS_RR_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('007c4f0c-8192-4806-9c25-c2f27ea4ba57')
    def test_PROXY_RR_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('0d6d2875-d1b3-4508-8e17-1c656a5f31ec')
    def test_PROXY_RR_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('9c968920-1fcc-4a71-8dc9-fdf2ff59af7c')
    def test_TCP_RR_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('1acd8a34-dd13-411e-bdf3-414b3fcc569d')
    def test_TCP_RR_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('2d154e0c-4955-4b00-92d5-e9df7b2fbf63')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_RR_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('06de8b15-caf3-4a75-b278-cdfe6208c8db')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_RR_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('6c88a35e-b7c1-4b14-bdae-1a710890555a')
    def test_HTTP_SI_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('266b60e2-7c3a-4edb-950b-66d57aa64b80')
    def test_HTTP_SI_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('c2c8ba90-6ade-4fd3-bf12-e15627983917')
    def test_HTTPS_SI_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('4af933ae-5c6d-4849-af85-e06f7d5a661c')
    def test_HTTPS_SI_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('383148a5-a9ec-413a-a44c-85c1bbb39729')
    def test_PROXY_SI_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('518c4d3f-2b5a-4f8a-9c5e-fad15127502e')
    def test_PROXY_SI_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('9b95b5f2-8823-4019-be86-311a1bde5b20')
    def test_TCP_SI_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('d8576e58-e8ff-491d-beee-b7c439d2c41c')
    def test_TCP_SI_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('896acc77-3b73-4565-ad87-9467218b143b')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SI_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('ffc64ff1-ec8c-4201-a295-a179adc0c7e0')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SI_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('7c4fcb3e-a994-4d39-97cc-929c022c001e')
    def test_HTTP_SIP_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('704d04c3-e639-4dee-b55d-09ebf55f8a0d')
    def test_HTTP_SIP_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('69de0c60-3e4f-40cf-9bf7-d2b1e6c83715')
    def test_HTTPS_SIP_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('2d970b1c-c157-4974-b605-b8e08d97e874')
    def test_HTTPS_SIP_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('28e1e3e7-454b-409d-84c3-1826f82ca9dd')
    def test_PROXY_SIP_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('189ec327-b1c5-47a8-a843-10963cba0a9c')
    def test_PROXY_SIP_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('6953a9a4-5fac-4470-bfda-4fafbd67288b')
    def test_TCP_SIP_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('6d8d546f-8c41-49b9-bd9d-8f8ea3975816')
    def test_TCP_SIP_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id)

    @decorators.idempotent_id('9c0d4668-5a0e-41b3-b3b4-3d0372fe28af')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SIP_alt_monitor_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('a03d02d0-830c-4aad-a10b-96c47974483c')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SIP_member_show(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_show(pool_id)

    def _test_member_show(self, pool_id, alternate_monitor=False):
        """Tests member show API.

        * Create a fully populated member.
        * Show member details.
        * Validate the show reflects the requested values.
        * Validates that other accounts cannot see the member.
        """
        member_name = data_utils.rand_name("lb_member_member1-show")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: pool_id,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: self.member_port.increment(),
            const.WEIGHT: 50,
        }
        if alternate_monitor:
            member_kwargs[const.MONITOR_ADDRESS] = '192.0.2.2'
            member_kwargs[const.MONITOR_PORT] = 8080

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_kwargs.update({
                const.BACKUP: False,
            })
        if self.lb_member_vip_subnet:
            member_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        member = self.mem_member_client.create_member(**member_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)

        parser.parse(member[const.CREATED_AT])
        parser.parse(member[const.UPDATED_AT])
        UUID(member[const.ID])
        self.assertEqual(const.NO_MONITOR, member[const.OPERATING_STATUS])

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if alternate_monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]

        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

        # Test that the appropriate users can see or not see the member
        # based on the API RBAC.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_system_reader',
                                'os_roles_lb_admin',
                                'os_roles_lb_global_observer',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_show_RBAC_enforcement(
                'MemberClient', 'show_member',
                expected_allowed, member[const.ID],
                pool_id=pool_id)

    @decorators.idempotent_id('65680d48-1d49-4959-a7d1-677797e54f6b')
    def test_HTTP_LC_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('52124440-c95c-48fb-af26-70377bcba7d6')
    def test_HTTP_LC_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('caf95728-5e9c-4295-bd4a-a15263ba5714')
    def test_HTTPS_LC_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('d1d98798-20cb-4290-818c-e814911d25e5')
    def test_HTTPS_LC_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('b22288fa-4e25-4779-bd78-6b4802926457')
    def test_PROXY_LC_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('5ee3df40-381a-4497-9e31-df82d8c2e514')
    def test_PROXY_LC_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('b693b5ba-d8e7-4b89-ad6c-41b56cf258f7')
    def test_TCP_LC_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('0df9463f-de6b-43c1-934f-6523873f3530')
    def test_TCP_LC_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('60baa2d7-927a-4b58-80b9-a2e5196985ee')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_LC_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('b036a40f-d220-4be6-abc9-8ca8e01b96c3')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_LC_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('c07572b8-e853-48f3-a8ea-37fc293a4724')
    def test_HTTP_RR_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('f83993ce-b053-42ff-9022-612ed67e8db6')
    def test_HTTP_RR_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('e419d49f-22e4-4331-985e-3a1cc8d0b6b0')
    def test_HTTPS_RR_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('42ac5187-799a-4714-972c-fea6e1c6a7b2')
    def test_HTTPS_RR_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('43d30b1d-0f99-4b46-ad37-542e899ceae7')
    def test_PROXY_RR_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('d5cf47a6-a3bb-4238-a5cf-a74b122edce4')
    def test_PROXY_RR_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('5a05f8b0-52ca-4ed7-a1a7-c62aee16c960')
    def test_TCP_RR_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('46e5d4e8-0ecc-40a7-87bd-f9ccdfc9a2d3')
    def test_TCP_RR_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('7609cd2f-32ac-4488-869a-7e14827df6ef')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_RR_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('171ae461-af7d-4fe1-961d-78376fcc2b3f')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_RR_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('af40e333-caed-4808-a46c-05c977f3cebc')
    def test_HTTP_SI_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('f63a9deb-4a45-42c4-9aeb-f7c304ecbc16')
    def test_HTTP_SI_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('27c17512-51b4-49ae-ac92-3e141599cdda')
    def test_HTTPS_SI_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('cc67064f-becc-4e31-b9e5-b3ea7e78a187')
    def test_HTTPS_SI_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('2061a0cf-49e0-49b8-af4d-f197cf84ef11')
    def test_PROXY_SI_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('5946b163-8684-402a-b228-c0648a3e0734')
    def test_PROXY_SI_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('7a6314dd-83c5-41ee-92f6-e18409ac213d')
    def test_TCP_SI_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('93818084-a9fb-480d-a7e1-04066ee0e393')
    def test_TCP_SI_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('523cf4e8-c071-4778-bc89-367a0b8469e6')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SI_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('9f655415-13d6-4ceb-9ea6-9a32baf0e093')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SI_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('5215ecc4-fd47-451a-b073-399bad8b522c')
    def test_HTTP_SIP_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('7c89fb05-d949-4c0f-8c61-7e55e494c76f')
    def test_HTTP_SIP_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('edff98be-6208-4f1c-9cd3-376b7ac47f80')
    def test_HTTPS_SIP_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('a1f214fe-6c09-4298-b03e-7069b615dec2')
    def test_HTTPS_SIP_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('56a21d8e-825a-4780-a073-41061a0d55ca')
    def test_PROXY_SIP_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('25a24e27-218b-4dcd-99aa-e9ca9f8163e5')
    def test_PROXY_SIP_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('d6625773-2665-423d-8500-cf9b1b38b53e')
    def test_TCP_SIP_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('87a3e3aa-580a-41ca-bc15-8cb2995c9125')
    def test_TCP_SIP_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id)

    @decorators.idempotent_id('796a2972-38e6-41fc-a885-6316195acd70')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SIP_alt_monitor_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id, alternate_monitor=True)

    @decorators.idempotent_id('2f4efa91-e61d-4dd6-8006-ebfdb00c1246')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SIP_member_update(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_update(pool_id)

    def _test_member_update(self, pool_id, alternate_monitor=False):
        """Tests member show API and field filtering.

        * Create a fully populated member.
        * Show member details.
        * Validate the show reflects the initial values.
        * Validates that other accounts cannot update the member.
        * Update the member details.
        * Show member details.
        * Validate the show reflects the initial values.
        """
        member_name = data_utils.rand_name("lb_member_member1-update")
        member_kwargs = {
            const.NAME: member_name,
            const.ADMIN_STATE_UP: False,
            const.POOL_ID: pool_id,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: self.member_port.increment(),
            const.WEIGHT: 50,
        }
        if alternate_monitor:
            member_kwargs[const.MONITOR_ADDRESS] = '192.0.2.2'
            member_kwargs[const.MONITOR_PORT] = 8080

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_kwargs.update({
                const.BACKUP: False,
            })

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            member_tags = ["Hello", "World"]
            member_kwargs.update({
                const.TAGS: member_tags
            })

        if self.lb_member_vip_subnet:
            member_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        member = self.mem_member_client.create_member(**member_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        status = const.OFFLINE
        if CONF.load_balancer.test_with_noop:
            status = const.NO_MONITOR
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.OPERATING_STATUS,
            status,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)

        parser.parse(member[const.CREATED_AT])
        parser.parse(member[const.UPDATED_AT])
        UUID(member[const.ID])

        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.ADDRESS,
                       const.PROTOCOL_PORT, const.WEIGHT]

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(member_kwargs[const.TAGS],
                                  member[const.TAGS])

        if alternate_monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]

        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

        # Test that a user, without the loadbalancer member role, cannot
        # update this member.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'MemberClient', 'update_member',
                expected_allowed, None, None, member[const.ID],
                pool_id=pool_id, admin_state_up=True)

        # Assert we didn't go into PENDING_*
        member_check = self.mem_member_client.show_member(
            member[const.ID], pool_id=pool_id)
        self.assertEqual(const.ACTIVE,
                         member_check[const.PROVISIONING_STATUS])
        self.assertEqual(member_kwargs[const.ADMIN_STATE_UP],
                         member_check[const.ADMIN_STATE_UP])

        new_name = data_utils.rand_name("lb_member_member1-UPDATED")
        member_update_kwargs = {
            const.POOL_ID: member_kwargs[const.POOL_ID],
            const.NAME: new_name,
            const.ADMIN_STATE_UP: not member[const.ADMIN_STATE_UP],
            const.WEIGHT: member[const.WEIGHT] + 1,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member_update_kwargs.update({
                const.BACKUP: not member[const.BACKUP]
            })

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            new_tags = ["Hola", "Mundo"]
            member_update_kwargs.update({
                const.TAGS: new_tags
            })

        if alternate_monitor:
            member_update_kwargs[const.MONITOR_ADDRESS] = '192.0.2.3'
            member_update_kwargs[const.MONITOR_PORT] = member[
                const.MONITOR_PORT] + 1
        member = self.mem_member_client.update_member(
            member[const.ID], **member_update_kwargs)
        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer, self.lb_id,
            const.PROVISIONING_STATUS, const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)
        # Operating status will be NO_MONITOR regardless of noop
        member = waiters.wait_for_status(
            self.mem_member_client.show_member,
            member[const.ID], const.OPERATING_STATUS,
            const.NO_MONITOR,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout,
            pool_id=pool_id)

        # Test changed items
        equal_items = [const.NAME, const.ADMIN_STATE_UP, const.WEIGHT]

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            equal_items.append(const.BACKUP)

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.5'):
            self.assertCountEqual(member_update_kwargs[const.TAGS],
                                  member[const.TAGS])

        if alternate_monitor:
            equal_items += [const.MONITOR_ADDRESS, const.MONITOR_PORT]

        for item in equal_items:
            self.assertEqual(member_update_kwargs[item], member[item])

        # Test unchanged items
        equal_items = [const.ADDRESS, const.PROTOCOL_PORT]
        if const.SUBNET_ID in member_kwargs:
            equal_items.append(const.SUBNET_ID)
        else:
            self.assertIsNone(member.get(const.SUBNET_ID))

        for item in equal_items:
            self.assertEqual(member_kwargs[item], member[item])

    @decorators.idempotent_id('8104628d-6f30-4037-ae65-c6f6c1b3af42')
    def test_HTTP_LC_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('c4331afe-c129-44e8-8388-fcbbd28cf783')
    def test_HTTP_LC_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                       alternate_monitor=True)

    @decorators.idempotent_id('5ed41de6-8994-4ba4-8107-29eab89fab1e')
    def test_HTTPS_LC_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('dd4d0a10-0473-47a2-8ec5-815fbdf0c5ee')
    def test_HTTPS_LC_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                       alternate_monitor=True)

    @decorators.idempotent_id('7ae0bd6f-d04c-4d53-bb7e-fef0680726db')
    def test_PROXY_LC_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('de033003-1dcb-4896-ad5d-9e68e31addf0')
    def test_PROXY_LC_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                       alternate_monitor=True)

    @decorators.idempotent_id('1d79ab5a-1110-43f1-bfc3-1cb4e2ab5011')
    def test_TCP_LC_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('69bd512a-d561-43b1-9a4a-ea7134ee8f9e')
    def test_TCP_LC_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                       alternate_monitor=True)

    @decorators.idempotent_id('b9fadfe2-c3f2-48a4-97a4-04c58c40df87')
    def test_UDP_LC_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS)

    @decorators.idempotent_id('f9a125e0-84c4-4f7e-8a82-fe84ca3175e5')
    def test_UDP_LC_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_LEAST_CONNECTIONS,
                                       alternate_monitor=True)

    @decorators.idempotent_id('5f412e52-8ee0-4ee5-8b0e-0e8fc68279a6')
    def test_HTTP_RR_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('83e0a9f2-491f-46a8-b3ce-6969d70a4e9f')
    def test_HTTP_RR_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_ROUND_ROBIN,
                                       alternate_monitor=True)

    @decorators.idempotent_id('ee622c92-a4b4-41a6-96e3-b3b2429276a2')
    def test_HTTPS_RR_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('7bed4b1c-f862-45bf-ae30-3b4ad0b48870')
    def test_HTTPS_RR_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_ROUND_ROBIN,
                                       alternate_monitor=True)

    @decorators.idempotent_id('82325d1a-ad01-471e-bfb3-b75ca86ae8eb')
    def test_PROXY_RR_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('098f73c5-e3c1-4dfa-bd7f-c87df90743e6')
    def test_PROXY_RR_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_ROUND_ROBIN,
                                       alternate_monitor=True)

    @decorators.idempotent_id('176cd46e-f5b1-47d1-9403-a0246272eea4')
    def test_TCP_RR_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('e952a399-c817-461e-9e37-fdf7e7b34983')
    def test_TCP_RR_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_ROUND_ROBIN,
                                       alternate_monitor=True)

    @decorators.idempotent_id('dec6b06d-6a69-48d9-b7a9-67eb287fe95a')
    def test_UDP_RR_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_ROUND_ROBIN)

    @decorators.idempotent_id('fdf2423c-c312-466a-b021-130a52b5be35')
    def test_UDP_RR_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_ROUND_ROBIN,
                                       alternate_monitor=True)

    @decorators.idempotent_id('546ac0c3-4025-4c88-8276-1c05e7198e82')
    def test_HTTP_SI_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('6c1fe175-8e99-4adf-934d-bee79c89fa02')
    def test_HTTP_SI_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_SOURCE_IP,
                                       alternate_monitor=True)

    @decorators.idempotent_id('3e6c76e0-3630-45f0-a674-5d79b662812b')
    def test_HTTPS_SI_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('59303a97-cc97-441e-b1a6-395271ec2287')
    def test_HTTPS_SI_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_SOURCE_IP,
                                       alternate_monitor=True)

    @decorators.idempotent_id('963d7e71-d8b7-4257-9b01-f1d7ab57cbc8')
    def test_PROXY_SI_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('f55d8bff-ac68-4e3b-8f05-a9bb69bb0881')
    def test_PROXY_SI_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_SOURCE_IP,
                                       alternate_monitor=True)

    @decorators.idempotent_id('71d20f78-ffe3-49a3-b0c6-38cd5804f255')
    def test_TCP_SI_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('fee72f7a-928d-477f-b09b-5a866be717a3')
    def test_TCP_SI_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_SOURCE_IP,
                                       alternate_monitor=True)

    @decorators.idempotent_id('086b407e-3ace-47a8-94e4-cf563674ceb6')
    def test_UDP_SI_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_SOURCE_IP)

    @decorators.idempotent_id('04259015-b6d7-411b-8c19-f21e05994b7c')
    def test_UDP_SI_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_SOURCE_IP,
                                       alternate_monitor=True)

    @decorators.idempotent_id('617028e2-89fb-4e7e-ba62-1a8a7af697ca')
    def test_HTTP_SIP_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('44a2508d-ecea-4f92-ba66-a64d6d7f12da')
    def test_HTTP_SIP_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTP,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT,
                                       alternate_monitor=True)

    @decorators.idempotent_id('794137e5-28c1-4b0e-bc2f-fc030d03a689')
    def test_HTTPS_SIP_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('c1c8930d-0436-4075-b47a-f3bd263ab8a8')
    def test_HTTPS_SIP_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.HTTPS,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT,
                                       alternate_monitor=True)

    @decorators.idempotent_id('1ab05cf2-265e-4291-b17c-19caa0a1b6ff')
    def test_PROXY_SIP_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('4de187b6-4948-4394-af6b-8828e96d8f3e')
    def test_PROXY_SIP_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.PROXY,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT,
                                       alternate_monitor=True)

    @decorators.idempotent_id('1d171080-c7e5-4ee0-83d4-51bb1655cb21')
    def test_TCP_SIP_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('52328f7a-bec4-4f23-9293-f5f1283c0af9')
    def test_TCP_SIP_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.TCP,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT,
                                       alternate_monitor=True)

    @decorators.idempotent_id('00b3ebda-c28c-471b-bbf8-01de6567b4b5')
    def test_UDP_SIP_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT)

    @decorators.idempotent_id('e4a357a3-1d07-46f4-a8ff-67a279783b24')
    def test_UDP_SIP_alt_monitor_member_batch_update(self):
        self._test_member_batch_update(const.UDP,
                                       const.LB_ALGORITHM_SOURCE_IP_PORT,
                                       alternate_monitor=True)

    def _test_member_batch_update(self, pool_protocol, algorithm,
                                  alternate_monitor=False):
        """Tests member batch update.

        * Create two members.
        * Batch update the members so one is deleted, created, and updated
        * Validate the member list is correct.
        """
        if (algorithm == const.LB_ALGORITHM_SOURCE_IP_PORT and not
            self.mem_listener_client.is_version_supported(
                self.api_version, '2.13')):
            raise testtools.TestCase.skipException(
                'Skipping this test as load balancing algorithm '
                'SOURCE_IP_PORT requires API version 2.13 or newer.')
        if (pool_protocol == const.UDP and
                not self.mem_listener_client.is_version_supported(
                    self.api_version, '2.1')):
            raise self.skipException('UDP support is only available '
                                     'in Octavia API version 2.1 or newer')

        pool_name = data_utils.rand_name("lb_member_pool3_member-batch")
        # This is a special case as the reference driver does not support
        # SOURCE-IP-PORT. Since it runs with not_implemented_is_error, we must
        # handle this test case special.
        try:
            pool = self.mem_pool_client.create_pool(
                name=pool_name, loadbalancer_id=self.lb_id,
                protocol=pool_protocol,
                lb_algorithm=algorithm)
        except exceptions.NotImplemented as e:
            if algorithm != const.LB_ALGORITHM_SOURCE_IP_PORT:
                raise
            message = ("The configured provider driver '{driver}' "
                       "does not support a feature required for this "
                       "test.".format(driver=CONF.load_balancer.provider))
            if hasattr(e, 'resp_body'):
                message = e.resp_body.get('faultstring', message)
            raise testtools.TestCase.skipException(message)

        pool_id = pool[const.ID]

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member1_name = data_utils.rand_name("lb_member_member1-batch")
        member1_kwargs = {
            const.NAME: member1_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: pool_id,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: 80,
            const.WEIGHT: 50,
        }
        if alternate_monitor:
            member1_kwargs[const.MONITOR_ADDRESS] = '192.0.2.2'
            member1_kwargs[const.MONITOR_PORT] = 8080

        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member1_kwargs.update({
                const.BACKUP: False,
            })

        if self.lb_member_vip_subnet:
            member1_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]
        member1 = self.mem_member_client.create_member(**member1_kwargs)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member2_name = data_utils.rand_name("lb_member_member2-batch")
        member2_kwargs = {
            const.NAME: member2_name,
            const.ADMIN_STATE_UP: True,
            const.POOL_ID: pool_id,
            const.ADDRESS: '192.0.2.3',
            const.PROTOCOL_PORT: 81,
            const.WEIGHT: 51,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member2_kwargs.update({
                const.BACKUP: True,
            })

        if alternate_monitor:
            member2_kwargs[const.MONITOR_ADDRESS] = '192.0.2.4'
            member2_kwargs[const.MONITOR_PORT] = 8081

        if self.lb_member_vip_subnet:
            member2_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        member2 = self.mem_member_client.create_member(**member2_kwargs)

        waiters.wait_for_status(self.mem_lb_client.show_loadbalancer,
                                self.lb_id,
                                const.PROVISIONING_STATUS,
                                const.ACTIVE,
                                CONF.load_balancer.build_interval,
                                CONF.load_balancer.build_timeout)

        member3_name = data_utils.rand_name("lb_member_member3-batch")
        member3_kwargs = {
            const.NAME: member3_name,
            const.ADMIN_STATE_UP: True,
            const.ADDRESS: '192.0.2.5',
            const.PROTOCOL_PORT: 82,
            const.WEIGHT: 52,
        }
        if self.mem_member_client.is_version_supported(
                self.api_version, '2.1'):
            member3_kwargs.update({
                const.BACKUP: True,
            })

        if alternate_monitor:
            member2_kwargs[const.MONITOR_ADDRESS] = '192.0.2.6'
            member2_kwargs[const.MONITOR_PORT] = 8082

        if self.lb_member_vip_subnet:
            member3_kwargs[const.SUBNET_ID] = self.lb_member_vip_subnet[
                const.ID]

        member2_name_update = data_utils.rand_name("lb_member_member2-new")
        member2_kwargs[const.NAME] = member2_name_update
        member2_kwargs.pop(const.POOL_ID)
        batch_update_list = [member2_kwargs, member3_kwargs]

        # Test that a user, without the loadbalancer member role, cannot
        # batch update this member.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_update_RBAC_enforcement(
                'MemberClient', 'update_members',
                expected_allowed, None, None,
                pool_id=pool_id, members_list=batch_update_list)

        # Assert we didn't go into PENDING_*
        member_check = self.mem_member_client.show_member(
            member2[const.ID], pool_id=pool_id)
        self.assertEqual(const.ACTIVE, member_check[const.PROVISIONING_STATUS])
        self.assertEqual(member2_name, member_check[const.NAME])

        self.mem_member_client.update_members(
            pool_id=pool_id, members_list=batch_update_list)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        members = self.mem_member_client.list_members(
            pool_id,
            query_params='{sort}={port}:{asc}'.format(
                sort=const.SORT, port=const.PROTOCOL_PORT, asc=const.ASC))

        # We should have two members: member2 and member3, in that order
        self.assertEqual(2, len(members))
        # Member2 is the same ID
        self.assertEqual(member2[const.ID], members[0][const.ID])
        # Member3 will have a different ID (not member1)
        self.assertNotEqual(member1[const.ID], members[1][const.ID])

        # Member2's name should be updated, and member3 should exist
        self.assertEqual(member2_name_update, members[0][const.NAME])
        self.assertEqual(member3_name, members[1][const.NAME])

    @decorators.idempotent_id('8b6574a3-17e8-4950-b24e-66d0c28960d3')
    def test_HTTP_LC_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('a122557b-4824-4a4f-87f0-6ba5c9ca1e32')
    def test_HTTPS_LC_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('069b8558-138f-4d6c-a3ec-9e803d5e2a14')
    def test_PROXY_LC_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('9b2a08cf-c9ae-4f8a-a15c-2acab09a7613')
    def test_TCP_LC_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('5824438d-cda2-4cea-a7d0-e7f5e5a11cac')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_LC_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_LEAST_CONNECTIONS)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('f129ba5e-a16e-4178-924f-6a9c5b8b1589')
    def test_HTTP_RR_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('f961105a-9874-4765-b457-3de9f342e226')
    def test_HTTPS_RR_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('6bca4760-bfb4-4cee-b77f-a77abec3e38e')
    def test_PROXY_RR_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('f0f5a651-f7f0-40d7-a051-32da07c28252')
    def test_TCP_RR_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('03424069-302d-4020-996c-0a346a97c847')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_RR_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_ROUND_ROBIN)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('87d0eac7-e391-4633-88cb-e691eeeab4fc')
    def test_HTTP_SI_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('a919aa78-5221-4321-aa26-fcd3432d843c')
    def test_HTTPS_SI_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('92368eef-d9ce-47d9-b3f2-7624601010a0')
    def test_PROXY_SI_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('1631c730-f34a-4ae7-91eb-5f5b5052cb55')
    def test_TCP_SI_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('8e05deee-f385-44d8-a112-2649aeea6006')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SI_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('1c9f9dc5-4ba3-44cd-a840-fd0629abfddd')
    def test_HTTP_SIP_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTP, pool_protocol=const.HTTP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('93ef7ac1-da00-420d-a367-22e86d968e1c')
    def test_HTTPS_SIP_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.HTTPS, pool_protocol=const.HTTPS,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('e83b9389-768f-4bcf-a650-17af01243d2b')
    def test_PROXY_SIP_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.PROXY,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('eca3d41d-21bd-4547-b8b8-8f87867eb4ad')
    def test_TCP_SIP_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.TCP, pool_protocol=const.TCP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_delete(pool_id)

    @decorators.idempotent_id('23788358-ac5f-46c4-922a-164e6a13fe0d')
    # Skipping test for amphora driver until "UDP load balancers cannot mix
    # protocol versions" (https://storyboard.openstack.org/#!/story/2003329) is
    # fixed
    @decorators.skip_because(
        bug='2003329',
        bug_type='storyboard',
        condition=(CONF.load_balancer.provider in const.AMPHORA_PROVIDERS and
                   CONF.load_balancer.test_with_ipv6))
    def test_UDP_SIP_member_delete(self):
        pool_id = self._listener_pool_create(
            listener_protocol=const.UDP, pool_protocol=const.UDP,
            algorithm=const.LB_ALGORITHM_SOURCE_IP_PORT)
        self._test_member_delete(pool_id)

    def _test_member_delete(self, pool_id):
        """Tests member create and delete APIs.

        * Creates a member.
        * Validates that other accounts cannot delete the member
        * Deletes the member.
        * Validates the member is in the DELETED state.
        """
        member_name = data_utils.rand_name("lb_member_member1-delete")
        member_kwargs = {
            const.POOL_ID: pool_id,
            const.NAME: member_name,
            const.ADDRESS: '192.0.2.1',
            const.PROTOCOL_PORT: self.member_port.increment(),
        }
        member = self.mem_member_client.create_member(**member_kwargs)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.build_interval,
            CONF.load_balancer.build_timeout)

        # Test that a user without the loadbalancer role cannot delete this
        # member.
        expected_allowed = []
        if CONF.load_balancer.RBAC_test_type == const.OWNERADMIN:
            expected_allowed = ['os_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.KEYSTONE_DEFAULT_ROLES:
            expected_allowed = ['os_system_admin', 'os_roles_lb_member']
        if CONF.load_balancer.RBAC_test_type == const.ADVANCED:
            expected_allowed = ['os_system_admin', 'os_roles_lb_admin',
                                'os_roles_lb_member']
        if expected_allowed:
            self.check_delete_RBAC_enforcement(
                'MemberClient', 'delete_member',
                expected_allowed, None, None, member[const.ID],
                pool_id=pool_id)

        self.mem_member_client.delete_member(member[const.ID],
                                             pool_id=pool_id)

        waiters.wait_for_deleted_status_or_not_found(
            self.mem_member_client.show_member, member[const.ID],
            const.PROVISIONING_STATUS,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout,
            pool_id=pool_id)

        waiters.wait_for_status(
            self.mem_lb_client.show_loadbalancer,
            self.lb_id, const.PROVISIONING_STATUS,
            const.ACTIVE,
            CONF.load_balancer.check_interval,
            CONF.load_balancer.check_timeout)
