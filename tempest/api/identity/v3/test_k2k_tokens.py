# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
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

from oslo_utils import timeutils
import six
from tempest.api.identity import base
from tempest import test

from tempest.lib.services.identity.v3 import k2k_token_client

class K2KTokensV3Test(base.BaseIdentityV3Test):

    @test.idempotent_id('6f8e4436-fc96-4282-8122-e41df57197a9')
    def test_unscoped_token(self):

#        creds = self.os.credentials
#        user_id = creds.user_id
#        username = creds.username
#        password = creds.password
#        user_domain_id = creds.user_domain_id

        # TODO move to base credential setup
        idp_auth_url = 'http://localhost:5000/v3/auth/tokens'
        idp_base_url = 'http://localhost:5000/v3'
        username = 'admin'
        password = 'nomoresecrete'
        project_name = 'admin'
        project_domain_id = 'default'
        user_domain_id = 'default'
        sp_id = 'ansible-sp'
        sp_project_name = 'admin'
        sp_project_domain_id = 'default'
        sp_ip = '128.52.184.143'
        #sp_url = "http://128.52.184.143:5000/v3/auth/tokens"

        remote_url = "http://128.52.184.143:35357/v3/OS-FEDERATION/identity_providers/keystone-idp/protocols/saml2/auth"

        # Get idp (local) auth token for saml2 exchange
        k2k_client = k2k_token_client.K2KTokenClient(auth_url=idp_auth_url)
        #idp_token, resp = self.non_admin_token.get_token(
        idp_token, resp = k2k_client.get_token(
            username=username,
            password=password,
            project_name=project_name,
            project_domain_id=project_domain_id,
            auth_data=True)

        # check if idp_token is valid
        self.assertNotEmpty(idp_token)
        self.assertIsInstance(idp_token, six.string_types)
        now = timeutils.utcnow()
        expires_at = timeutils.normalize_time(
            timeutils.parse_isotime(resp['expires_at']))
        self.assertGreater(resp['expires_at'],
                           resp['issued_at'])
        self.assertGreater(expires_at, now)
        subject_name = resp['user']['name']
        self.assertEqual(subject_name, username)
        self.assertEqual(resp['methods'][0], 'password')

        assertion = k2k_client._get_ecp_assertion(
            sp_id=sp_id, token=idp_token)
        
        #import pdb; pdb.set_trace()
        unscoped_token_id = k2k_client.get_unscoped_token(sp_ip, assertion)
         
        #scoped_token = k2k_client.get_scoped_token(unscoped_token_id, sp_project_name, sp_project_domain_id)
