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
    def test_get_unscoped_scoped_token(self):
        idp_auth_url = 'http://localhost:5000/v3/auth/tokens'
        sp_auth_url = "http://128.52.184.143:5000/v3/auth/tokens"
        sp_project_id = 'f47e162ee69a4631abd7f69b084ab32e'
        username = 'admin'
        password = 'nomoresecrete'
        project_name = 'admin'
        project_domain_id = 'default'
        sp_id = 'ansible-sp'
        sp_ip = '128.52.184.143'

        k2k_client = k2k_token_client.K2KTokenClient(auth_url=idp_auth_url)
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

        assertion = k2k_client._get_ecp_assertion(sp_id=sp_id,
                                                  token=idp_token)
        unscoped_token = k2k_client.get_unscoped_token(sp_ip, assertion)
        # check if unscoped_token is valid
        self.assertNotEmpty(unscoped_token)
        self.assertIsInstance(unscoped_token, six.string_types)
        now = timeutils.utcnow()
        expires_at = timeutils.normalize_time(
            timeutils.parse_isotime(resp['expires_at']))
        self.assertGreater(resp['expires_at'],
                           resp['issued_at'])
        self.assertGreater(expires_at, now)
        subject_name = resp['user']['name']
        self.assertEqual(subject_name, username)
        self.assertEqual(resp['methods'][0], 'password')

        sp_client = k2k_token_client.K2KTokenClient(auth_url=sp_auth_url)
        scoped_token = sp_client.get_scoped_token(unscoped_token, 
                                                  sp_project_id)
        # check if scoped_token is valid
        self.assertNotEmpty(scoped_token)
        self.assertIsInstance(scoped_token, six.string_types)
        now = timeutils.utcnow()
        expires_at = timeutils.normalize_time(
            timeutils.parse_isotime(resp['expires_at']))
        self.assertGreater(resp['expires_at'],
                           resp['issued_at'])
        self.assertGreater(expires_at, now)
        subject_name = resp['user']['name']
        self.assertEqual(subject_name, username)
        self.assertEqual(resp['methods'][0], 'password')
