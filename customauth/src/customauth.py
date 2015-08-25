#Copyright (c) 2015 OpenStack Foundation, La Salle URL, Alex Roig
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Version 1.3
from __future__ import print_function

from time import time
from datetime import datetime
from dateutil import parser
from traceback import format_exc
from urllib import unquote
from uuid import uuid4
from hashlib import sha1
import hmac
import base64
import urllib
import urllib2
import json
from eventlet import Timeout
from swift.common.swob import Response, Request
from swift.common.swob import HTTPBadRequest, HTTPForbidden, HTTPNotFound, \
    HTTPUnauthorized

from swift.common.request_helpers import get_sys_meta_prefix
from swift.common.middleware.acl import (
    clean_acl, parse_acl, referrer_allowed, acls_from_account_info)
from swift.common.utils import cache_from_env, get_logger, \
    split_path, config_true_value, register_swift_info
from swift.proxy.controllers.base import get_account_info


class CustomAuth(object):
    def __init__(self, app, conf):
        """
        This function is called when Swift Proxy inits.
        """
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='customauth')
        self.log_headers = config_true_value(conf.get('log_headers', 'f'))
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH').strip()
        if self.reseller_prefix and self.reseller_prefix[-1] != '_':
            self.reseller_prefix += '_'
        self.logger.set_statsd_prefix('customauth.%s' % (
            self.reseller_prefix if self.reseller_prefix else 'NONE',))
        self.auth_prefix = conf.get('auth_prefix', '/auth/')
        #Organization
        self.organization_id = conf.get('organization_id', '57b69c457792482c8d817c4945c6c8a8')


        #Keystone
        self.keystone_auth_endpoint = conf.get('keystone_auth_endpoint', 'http://cloud.lab.fiware.org:4730/v2.0/tokens')
        self.keystone_tenant_endpoint = conf.get('keystone_tenant_endpoint', 'http://cloud.lab.fiware.org:4730/v2.0/tenants')
        if not self.auth_prefix or not self.auth_prefix.strip('/'):
            self.logger.warning('Rewriting invalid auth prefix "%s" to '
                                '"/auth/" (Non-empty auth prefix path '
                                'is required)' % self.auth_prefix)
            self.auth_prefix = '/auth/'
        if self.auth_prefix[0] != '/':
            self.auth_prefix = '/' + self.auth_prefix
        if self.auth_prefix[-1] != '/':
            self.auth_prefix += '/'
        self.token_life = int(conf.get('token_life', 86400))
        self.allow_overrides = config_true_value(
            conf.get('allow_overrides', 't'))
        self.storage_url_scheme = conf.get('storage_url_scheme', 'default')
        self.logger.info('CustomAuth v1.3 loaded successfully')


    def __call__(self, env, start_response):
        """
        This function is called when a requests reaches this WSGI module.
        It's the entry point for requests.
        """
        self.logger.info('CP 1')
        if self.allow_overrides and env.get('swift.authorize_override', False):
            self.logger.info('CP 1.1')
            return self.app(env, start_response)
        if env.get('PATH_INFO', '').startswith(self.auth_prefix):
            self.logger.info('CP 1.2')
            return self.handle(env, start_response)
        s3 = env.get('HTTP_AUTHORIZATION')
        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        self.logger.info('CP 2')
        if token:
            # Note: Empty reseller_prefix will match all tokens.

            self.logger.info('CP 3')
            memcache_client = cache_from_env(env)
            if not memcache_client:
                raise Exception('Memcache required')
            memcache_token_key =  '%s/token/%s' % (self.reseller_prefix, token)
            path_info_total = env.get('PATH_INFO')
            self.logger.info('PATH_INFO = '+path_info_total)
            strings = path_info_total.split('/') 
            public = False
            tenant_url = None
            for string in strings:
                if 'AUTH_' in string.upper():
                    tenant_url = string
                    tenant_url = tenant_url.upper()[5:]
                if 'PUB_' in string.upper():
                    public = True
            cached_auth_data = memcache_client.get(memcache_token_key)

            self.logger.info('CP 3.1')
            if cached_auth_data:
                try:
                    self.logger.info('CP 3.2')
                    user, tenant, expiry = cached_auth_data.split('&')
                    if all((user, tenant, expiry)):
                        if float(expiry) > time():
                            tenant = tenant.upper();
                            self.logger.info('CP 3.3')
                            if tenant == tenant_url:
                                self.logger.info('validated')
                                env['swift.authorize'] = self.authorize
                                env['swift.clean_acl'] = clean_acl
                                #self.logger.info('start_response = ' + str((env)))
                                return self.app(env, start_response)   
                            elif public:
                                self.logger.info('validated')
                                env['swift.authorize'] = self.authorize
                                env['swift.clean_acl'] = clean_acl
                                self.logger.info('Public Authorization')
                                return self.app(env, start_response) 
                            else:
                                return HTTPForbidden(headers={
                                        'Www-Authorization':'Permission Denied'})(
                                        env, start_response)                      
                except ValueError:
                    self.logger.info('Error parsing')
                    memcache_client.delete(memcache_user_key)
            return HTTPUnauthorized(headers={
                            'Www-Authenticate': 'Swift realm="%s"' % 'invalid token'})(
                            env, start_response)

        else:
            self.logger.info('CP 5')
            if self.reseller_prefix:
                self.logger.info('CP 5.1')
                # With a non-empty reseller_prefix, I would like to be called
                # back for anonymous access to accounts I know I'm the
                # definitive auth for.
                try:
                    version, rest = split_path(env.get('PATH_INFO', ''),
                                               1, 2, True)
                    self.logger.info('Version = '+ version)
                    #self.logger.info('Rest = ' + rest)
                    # Important!! By default REST = '' -> Modified input...
                except ValueError:
                    version, rest = None, None
                    self.logger.increment('errors')
                if rest and rest.startswith(self.reseller_prefix):
                    self.logger.info('CP 5.2')
                    # Handle anonymous access to accounts I'm the definitive
                    # auth for.
                    env['swift.authorize'] = self.authorize
                    env['swift.clean_acl'] = clean_acl
                # Not my token, not my account, I can't authorize this request,
                # deny all is a good idea if not already set...
                elif 'swift.authorize' not in env:
                    self.logger.info('CP 5.3')
                    env['swift.authorize'] = self.denied_response
            # Because I'm not certain if I'm the definitive auth for empty
            # reseller_prefixed accounts, I won't overwrite swift.authorize.


            elif 'swift.authorize' not in env:
                self.logger.info('CP 5.4')
                env['swift.authorize'] = self.authorize
                env['swift.clean_acl'] = clean_acl
        self.logger.info('CP 6')
        return self.app(env, start_response)


    def account_acls(self, req):
        """
        Return a dict of ACL data from the account server via get_account_info.

        Auth systems may define their own format, serialization, structure,
        and capabilities implemented in the ACL headers and persisted in the
        sysmeta data.  However, auth systems are strongly encouraged to be
        interoperable with Tempauth.

        Account ACLs are set and retrieved via the header
           X-Account-Access-Control

        For header format and syntax, see:
         * :func:`swift.common.middleware.acl.parse_acl()`
         * :func:`swift.common.middleware.acl.format_acl()`
        """
        info = get_account_info(req.environ, self.app, swift_source='TA')
        try:
            acls = acls_from_account_info(info)
        except ValueError as e1:
            self.logger.warn("Invalid ACL stored in metadata: %r" % e1)
            return None
        except NotImplementedError as e2:
            self.logger.warn("ACL version exceeds middleware version: %r" % e2)
            return None
        return acls

    def authorize(self, req):
        """
        Returns None if the request is authorized to continue or a standard
        WSGI response callable if not.
        """
        return None
        
    def denied_response(self, req):
        """
        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            self.logger.increment('forbidden')
            return HTTPForbidden(request=req)
        else:
            self.logger.increment('unauthorized')
            return HTTPUnauthorized(request=req)

    def handle(self, env, start_response):
        """
        WSGI entry point for auth requests (ones that match the
        self.auth_prefix).
        Wraps env in swob.Request object and passes it down.

        :param env: WSGI environment dictionary
        :param start_response: WSGI callable
        """
        try:
            req = Request(env)
            if self.auth_prefix:
                req.path_info_pop()
            req.bytes_transferred = '-'
            req.client_disconnect = False
            if 'x-storage-token' in req.headers and \
                    'x-auth-token' not in req.headers:
                req.headers['x-auth-token'] = req.headers['x-storage-token']
            return self.handle_request(req)(env, start_response)
        except (Exception, Timeout):
            print("EXCEPTION IN handle: %s: %s" % (format_exc(), env))
            self.logger.increment('errors')
            start_response('500 Server Error',
                           [('Content-Type', 'text/plain')])
            return ['Internal server error.\n']

    def handle_request(self, req):
        """
        Entry point for auth requests (ones that match the self.auth_prefix).
        Should return a WSGI-style callable (such as swob.Response).

        :param req: swob.Request object
        """
        req.start_time = time()
        handler = None
        try:
            version, account, user, _junk = req.split_path(1, 4, True)
        except ValueError:
            self.logger.increment('errors')
            return HTTPNotFound(request=req)
        if version in ('v1', 'v1.0', 'auth'):
            if req.method == 'GET':
                handler = self.handle_get_token
        if not handler:
            self.logger.increment('errors')
            req.response = HTTPBadRequest(request=req)
        else:
            req.response = handler(req)
        return req.response

    def handle_get_token(self, req):
        """
        Handles the various `request for token and service end point(s)` calls.
        There are various formats to support the various auth servers in the
        past. Examples::

            GET <auth-prefix>/v1/<act>/auth
                X-Auth-User: <act>:<usr>  or  X-Storage-User: <usr>
                X-Auth-Key: <key>         or  X-Storage-Pass: <key>
            GET <auth-prefix>/auth
                X-Auth-User: <act>:<usr>  or  X-Storage-User: <act>:<usr>
                X-Auth-Key: <key>         or  X-Storage-Pass: <key>
            GET <auth-prefix>/v1.0
                X-Auth-User: <act>:<usr>  or  X-Storage-User: <act>:<usr>
                X-Auth-Key: <key>         or  X-Storage-Pass: <key>

        On successful authentication, the response will have X-Auth-Token and
        X-Storage-Token set to the token to use with Swift and X-Storage-URL
        set to the URL to the default Swift cluster to use.

        :param req: The swob.Request to process.
        :returns: swob.Response, 2xx on success with data set as explained
                  above.
        """
        # Validate the request info
        self.logger.info('CheckPoint HGT 1')
        try:
            pathsegs = split_path(req.path_info, 1, 3, True)
        except ValueError:
            self.logger.increment('errors')
            return HTTPNotFound(request=req)
        if pathsegs[0] == 'v1' and pathsegs[2] == 'auth':
            ## 
            self.logger.info('CheckPoint HGT 2')
            account = pathsegs[1]
            user = req.headers.get('x-storage-user')
            if not user:
                user = req.headers.get('x-auth-user')
                if not user or ':' not in user:
                    self.logger.increment('token_denied')
                    return HTTPUnauthorized(request=req, headers=
                                            {'Www-Authenticate':
                                             'Swift realm="%s"' % account})
                account2, user = user.split(':', 1)
                if account != account2:
                    self.logger.increment('token_denied')
                    return HTTPUnauthorized(request=req, headers=
                                            {'Www-Authenticate':
                                             'Swift realm="%s"' % account})
            key = req.headers.get('x-storage-pass')
            if not key:
                key = req.headers.get('x-auth-key')
        elif pathsegs[0] in ('auth', 'v1.0'):
            self.logger.info('CheckPoint HGT 3')
            user = req.headers.get('x-auth-user')
            if not user:
                user = req.headers.get('x-storage-user')
            if not user:
                self.logger.increment('token_denied')
                return HTTPUnauthorized(request=req, headers=
                                        {'Www-Authenticate':
                                         'Swift realm="unknown"'})
            #account, user = user.split(':', 1)
            key = req.headers.get('x-auth-key')
            if not key:
                key = req.headers.get('x-storage-pass')

            self.logger.info('User = ' + user)
            self.logger.info('Key = ' +key)
        else:
            return HTTPBadRequest(request=req)
        if not all((user, key)):
            self.logger.increment('token_denied')
            realm = account or 'unknown'
            return HTTPUnauthorized(request=req, headers={'Www-Authenticate':
                                                          'Swift realm="%s"' %
                                                          realm})
        # Authenticate user

        #######################################################################################
        ######## CHECK IN MEMCACHE ############################################################
        #######################################################################################
        account_user = user
        memcache_client = cache_from_env(req.environ)
        if not memcache_client:
            raise Exception('Memcache required')

        memcache_user_key = '%s/user/%s/key/%s' % (self.reseller_prefix, user, key)
        candidate_token = memcache_client.get(memcache_user_key)
        if candidate_token:
            self.logger.info('Candidate token found in memcache. Content is :' + candidate_token)
            try:
                token, tenant, expiry = candidate_token.split('&')
                if all((token, tenant, expiry)):
                    if float(expiry) > time():
                        resp = Response(request=req, headers={'x-auth-token': token, 'x-storage-token': token})
                        resp.headers['x-storage-url'] = 'http://controller:8080/v1/AUTH_'+tenant
                        return resp
            except ValueError:
                self.logger.info('Error parsing')
                memcache_client.delete(memcache_user_key)

        #######################################################################################
        ######## GET KEYSTONE TEMPORARY TOKEN #################################################
        #######################################################################################

        uri = self.keystone_auth_endpoint
        try:    
            url = uri
            values = '{"auth": {"passwordCredentials": {"username": "'+ user+'", "password": "'+key+'" }}}'
            head = { 'Content-type' : 'application/json' }

            #data = urllib.urlencode(values)
            request_keystone = urllib2.Request(url, values, head)
            handle = urllib2.urlopen(request_keystone)
        except urllib2.HTTPError, e:
            self.logger.info('KR - Error %e...', e.code)
            if e.code == 401:
                self.logger.notice('KR - Unauthorized')
            return HTTPUnauthorized(request=req, headers=
                                     {'Www-Authenticate':
                                      'Swift realm="unknown"'})
        keystone_response = handle.read()
        temporary_token_json = json.loads(keystone_response)
        temporary_token = temporary_token_json['access']['token']['id']
        self.logger.info('Temporary token = ' + temporary_token)
        if not temporary_token:
            return HTTPUnauthorized(request=req, headers=
                                     {'Www-Authenticate':
                                      'Swift realm="Keystone failed to retrieve x-auth-token"'})

        #######################################################################################
        ######## GET KEYSTONE TENANT ID #######################################################
        #######################################################################################

        try:    
            values = ''
            head = { 'X-Auth-Token' : temporary_token , 'Content-type' : 'application/json'}

            #data = urllib.urlencode(values)
            request_keystone = urllib2.Request(self.keystone_tenant_endpoint, None,  head)
            handle = urllib2.urlopen(request_keystone)
        except urllib2.HTTPError, e:
            self.logger.info('KR - Error %e...', e.code)
            if e.code == 401:
                self.logger.notice('KR - Unauthorized')
            return HTTPUnauthorized(request=req, headers=
                                     {'Www-Authenticate':
                                      'Swift realm="unknown"'})
        tenant_list = json.loads(handle.read())
        tenants = tenant_list['tenants']
        tenant = ''
        organizationFound = False
        for e in tenants:
            try:
                if e['id'] == self.organization_id:
                    organizationFound = True
                    self.logger.info('Organization Found!')
                if e['is_default'] == True:
                    tenant = e['id']
                    name = e['name']
                
            except:
                pass
        if not organizationFound:
            return HTTPUnauthorized(request=req, headers=
                                     {'Www-Authenticate':
                                      'Swift realm="User has no valid Organization"'})        

        name = name + " cloud"
        for e in tenants:
            if e['name'] == name:
                tenant = e['id']
                name = e['name']
                hasPublicCloud = True
        self.logger.info('Tenant id = '+ tenant)
        if not tenant:
            return HTTPUnauthorized(request=req, headers=
                                     {'Www-Authenticate':
                                      'Swift realm="User has no valid tenant"'})

        #######################################################################################
        ######## GET DEFINITIVE TOKEN #########################################################
        #######################################################################################
        #if hasPublicCloud:
        """
        try:    
            values = '{"auth": {"tenantName": "'+tenant+'", "passwordCredentials": {"username": "'+user+'", "password": "'+key+'"}}}'
            head = { 'Content-type' : 'application/json', 'Accept' : 'application/json'}

            #data = urllib.urlencode(values)
            request_keystone = urllib2.Request(self.keystone_auth_endpoint, values,  head)
            handle = urllib2.urlopen(request_keystone)
        except urllib2.HTTPError, e:
            self.logger.info('KR - Error %e...', e.code)
            if e.code == 401:
                self.logger.notice('KR - Unauthorized')
            return HTTPUnauthorized(request=req, headers=
                                     {'Www-Authenticate':
                                      'Swift realm="unknown"'})

        json_data = json.loads(handle.read())
        """
        json_data = temporary_token_json
        token_expiry = json_data['access']['token']['expires']
        token_definitive = json_data['access']['token']['id']

        if token_expiry[len(token_expiry)-1] == 'Z':
            token_expiry = token_expiry[:-1]

        token_expiry = token_expiry.replace("T", " ")
        #token_expiry = "2015-05-19 07:56:34"
        token_expiry_date = parser.parse(token_expiry)
        seconds = (token_expiry_date - datetime.now()).seconds
        seconds = 86400
        
        self.logger.info('Expires = ' + token_expiry)
        self.logger.info('Seconds = ' + str(seconds))
        self.logger.info('Token = ' + token_definitive)
        self.logger.info('Expires in ' + str(seconds) + ' seconds')

        #Store data in memcache
        memcache_client = cache_from_env(req.environ)
        if not memcache_client:
            raise Exception('Memcache required')

        expires = time() + seconds
        memcache_user_key = '%s/user/%s/key/%s' % (self.reseller_prefix, account_user, key)
        memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token_definitive)
        memcache_token_value = '%s&%s&%s' % (token_definitive, tenant, expires)
        memcache_user_value = '%s&%s&%s' % (user, tenant, expires)
        memcache_client.set(memcache_token_key, memcache_user_value)
        memcache_client.set(memcache_user_key, memcache_token_value)


        resp = Response(request=req, headers={
            'x-auth-token': token_definitive, 'x-storage-token': token_definitive})
        resp.headers['x-storage-url'] = 'http://controller:8080/v1/AUTH_'+tenant
        return resp
##############################################################################################

        # Get memcache client
        memcache_client = cache_from_env(req.environ)
        if not memcache_client:
            raise Exception('Memcache required')
        # See if a token already exists and hasn't expired
        token = None
        memcache_user_key = '%s/user/%s/key/%s' % (self.reseller_prefix, account_user,key)
        candidate_token = memcache_client.get(memcache_user_key)
        if candidate_token:
            memcache_token_key = \
                '%s/token/%s' % (self.reseller_prefix, candidate_token)
            cached_auth_data = memcache_client.get(memcache_token_key)
            if cached_auth_data:
                expires, old_groups = cached_auth_data
                old_groups = old_groups.split(',')
                new_groups = self._get_user_groups(account, account_user,
                                                   account_id)

                if expires > time() and \
                        set(old_groups) == set(new_groups.split(',')):
                    token = candidate_token
        # Create a new token if one didn't exist
        if not token:
            # Generate new token
            token = '%stk%s' % (self.reseller_prefix, uuid4().hex)
            expires = time() + self.token_life
            groups = self._get_user_groups(account, account_user, account_id)
            # Save token
            memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
            memcache_client.set(memcache_token_key, (expires, groups),
                                time=float(expires - time()))
            # Record the token with the user info for future use.
            memcache_user_key = \
                '%s/user/%s' % (self.reseller_prefix, account_user)
            memcache_client.set(memcache_user_key, token,
                                time=float(expires - time()))
        resp = Response(request=req, headers={
            'x-auth-token': token, 'x-storage-token': token})
        url = self.users[account_user]['url'].replace('$HOST', resp.host_url)
        self.logger.info('URL = '+url)
        if self.storage_url_scheme != 'default':
            url = self.storage_url_scheme + ':' + url.split(':', 1)[1]
        resp.headers['x-storage-url'] = url
        return resp


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)
    register_swift_info('customauth', account_acls=True)

    def auth_filter(app):
        return CustomAuth(app, conf)
    return auth_filter