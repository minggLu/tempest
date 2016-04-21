# Copyright 2015 NEC Corporation.  All rights reserved.
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

from oslo_log import log as logging
from oslo_serialization import jsonutils as json

from tempest.lib.common import rest_client
from tempest.lib import exceptions
from tempest.lib.services.identity.v3 import token_client

import six

class K2KTokenClient(token_client.V3TokenClient):

    def __init__(self, auth_url,
                 disable_ssl_certificate_validation=None,
                 ca_certs=None, trace_requests=None):
        super(K2KTokenClient, self).__init__(auth_url)
#        dscv = disable_ssl_certificate_validation
#        super(K2KTokenClient, self).__init__(
#            None, None, None, disable_ssl_certificate_validation=dscv,
#            ca_certs=ca_certs, trace_requests=trace_requests)

        if auth_url is None:
            raise exceptions.IdentityError("Couldn't determine auth_url")


        self.auth_url = auth_url

    def _get_ecp_assertion(self, sp_id=None,token=None):
        """Obtains a token from the authentication service

        :param sp_id: registered Service Provider id in Identity Provider
        :param token: a token to perform K2K Federation.

        Accepts one combinations of credentials.
        - token, sp_id
        Validation is left to the Service Provider side.
        """
        body = {
            "auth": {
                "identity": {
                    "methods": [
                        "token"
                    ],
                    "token": {
                        "id": token
                    }
                },
                "scope": {
                    "service_provider": {
                        "id": sp_id
                    }
                }
            }
        }

        self.body = body
        PATTERN = '/auth/tokens'
        base_url = self.auth_url.split(PATTERN)[0]

        REQUEST_ECP_URL = '/auth/OS-FEDERATION/saml2/ecp'
        url = base_url + REQUEST_ECP_URL
        endpoint_filter = {'version': (3, 0),
                           'interface': 'public'}

        headers = {'Accept': 'application/json'}

        resp, body = self.post(url=url,
                               body=json.dumps(body, sort_keys=True),
                               headers=headers, saml='saml2')

        self.expected_success(200, resp.status)
#        if not resp.ok:
#            msg = ("Error while requesting ECP wrapped assertion: response "
#                   "exit code: %(status_code)d, reason: %(err)s")
#            msg = msg % {'status_code': resp.status_code, 'err': resp.reason}
#            raise exceptions.AuthorizationFailure(msg)
#
#        if not resp.text:
#            raise exceptions.InvalidResponse(resp)

        #return rest_client.ResponseBody(resp, body)
        return six.text_type(body)

    def get_unscoped_token(self, sp_ip, assertion):
        """Send assertion to a Keystone SP and get token."""

        ecp_url = 'http://' + sp_ip + ':5000/Shibboleth.sso/SAML2/ECP'
        auth_url = 'http://' + sp_ip + ':35357/v3/OS-FEDERATION/identity_providers/keystone-idp/protocols/saml2/auth'
        r, b = self.post(
            url=ecp_url,
            headers={'Content-Type': 'application/vnd.paos+xml'},
            body=assertion, saml='saml2')

        cookie = r['set-cookie'].split(';')[0]
        headers={'Content-Type': 'application/vnd.paos+xml',
                 'Cookie': cookie}
        resp, body = self.get(url=auth_url, headers=headers)

        print resp
        print body

        fed_token_id = resp['x-subject-token']
        return fed_token_id

    def get_scoped_token(self, _token, sp_ip, project_name, project_domain_id):
        # project_id can be select from the list in the previous step
        url = 'http://' + sp_ip + ':5000/v3/auth/tokens'
        headers = {'x-auth-token': _token,
                   'Content-Type': 'application/json'}
        resp, body = self.auth(auth_url=url, headers=headers, token=_token,
                      project_name=project_name,
                      project_domain_id=project_domain_id)
        self.expected_success(201, resp.status)
        scoped_token_id = resp['x-subject-token']
        #scoped_token_ref = str(body)
        return scoped_token_id
