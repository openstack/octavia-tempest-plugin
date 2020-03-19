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
import socket

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connection import HTTPConnection
from requests.packages.urllib3.poolmanager import PoolManager


class SourcePortAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to set the source port."""
    def __init__(self, port, *args, **kwargs):
        self._source_port = port
        super(SourcePortAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        # Make sure TIMED_WAIT doesn't stop us from reusing the socket
        sock_options = HTTPConnection.default_socket_options + [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1), ]
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, source_address=('', self._source_port),
            socket_options=sock_options)
