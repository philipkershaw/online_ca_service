"""Online CA Service client register module - provides simple client 
delegation mechanism

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "22/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)
from datetime import datetime

from OpenSSL import crypto
from paste.httpexceptions import HTTPUnauthorized

from contrail.security.onlineca.server.openssl_utils import X509SubjectName
from contrail.security.onlineca.server.wsgi.httpbasicauth import \
                                                    HttpBasicAuthMiddleware


class ClientRegisterMiddlewareError(Exception):
    '''Base class for Client Register exceptions'''
    
    
class ClientRegisterMiddlewareConfigError(ClientRegisterMiddlewareError):
    '''Parse error for Client Register config'''
    
    
class ClientRegisterMiddleware(object):
    '''Whitelist client requests based on SSL client certificate and username
    passed in HTTP basic auth header
    '''
    CLIENT_REGISTER_OPT_PREFIX = 'client_register.'
    DN_SUB_OPTNAME = 'dn'
    USERS_SUB_OPTNAME = 'user'
    DEFAULT_SSL_CLIENT_CERT_KEYNAME = 'SSL_CLIENT_CERT'
    SSL_CLIENT_CERT_KEYNAME_OPTNAME = 'ssl_client_cert_keyname'
    DEFAULT_USERID_KEYNAME = 'REMOTE_USER'
    USERID_KEYNAME_OPTNAME = 'userid_keyname'
    DEFAULT_PATH_MATCH_LIST = None
    PATH_MATCH_LIST_OPTNAME = 'path_match_list'
    X509_DATETIME_FMT = '%Y%m%d%H%M%S%fZ'
    
    def __init__(self, app):
        self.app = app
        self.client_register = {}
        self.ssl_client_cert_keyname = \
            self.__class__.DEFAULT_SSL_CLIENT_CERT_KEYNAME
        self.userid_keyname = self.__class__.DEFAULT_USERID_KEYNAME
        self.__path_match_list = self.__class__.DEFAULT_PATH_MATCH_LIST
    
    @property
    def path_match_list(self):
        return self.__path_match_list
    
    @path_match_list.setter
    def path_match_list(self, val):
        if isinstance(val, basestring):
            self.__path_match_list = val.split()
        elif isinstance(val, (list, tuple)):
            self.__path_match_list = tuple(val)
        else:
            raise TypeError('Expecting list, tuple or string type for '
                            '"path_match_list"; got %r type instead' % type(val))
            
    @classmethod
    def filter_app_factory(cls, app, global_conf, 
                           prefix='',
                           **app_conf):
        obj = cls(app)
        
        # Parse client register.  This has the form of a list of clients and 
        # the usernames for which they can get a delegation e.g.
        # 
        # client_register.0.dn = /O=NDG/OU=Security/CN=delegatee.somewhere.ac.uk
        # client_register.0.user0 = another jbloggs jdoe
        # client_register.1.dn = /O=STFC/OU=CEDA/CN=delegatee.ceda.ac.uk
        # client_register.1.user_1 = asmith 
        # 
        # would result in:
        #
        # client_register = {'/O=NDG/OU=Security/CN=delegatee.somewhere.ac.uk':
        #                    ['another', 'jbloggs', 'jdoe'],
        #                   '/O=STFC/OU=CEDA/CN=delegatee.ceda.ac.uk':
        #                    ['asmith']}
        client_register_opt_prefix = prefix + cls.CLIENT_REGISTER_OPT_PREFIX
        dn_lookup = {}
        users_lookup = {}
        for optname, val in app_conf.items():
            if optname.startswith(client_register_opt_prefix):
                identifier, sub_optname = optname.split('.')[-2:]
                                    
                if sub_optname == cls.DN_SUB_OPTNAME:
                    if sub_optname in dn_lookup:
                        raise ClientRegisterMiddlewareConfigError(
                                '%r duplicate option name found' % optname)
                        
                    subject_name = X509SubjectName.from_string(val)
                    dn_lookup[identifier] = subject_name.serialize()
                    
                elif sub_optname.startswith(cls.USERS_SUB_OPTNAME):
                    if identifier in users_lookup:
                        users_lookup[identifier].append(val)
                    else:
                        users_lookup[identifier] = [val]
                else:
                    raise ClientRegisterMiddlewareConfigError(
                        '%r option name not recognised' % optname)
                    
        # Match up DNs and usernames
        for identifier, dn in dn_lookup.items():
            obj.client_register[dn] = users_lookup.get(identifier, [])  

        # key name in environ which is expected to contain the SSL client
        # certificate
        ssl_client_cert_keyname_optname = prefix + \
                                            cls.SSL_CLIENT_CERT_KEYNAME_OPTNAME
        if ssl_client_cert_keyname_optname in app_conf:
            obj.ssl_client_cert_keyname = app_conf[
                                                ssl_client_cert_keyname_optname]
            
        userid_keyname_optname = prefix + cls.USERID_KEYNAME_OPTNAME
        if userid_keyname_optname in app_conf:
            obj.userid_keyname = app_conf[userid_keyname_optname]
            
        path_match_list_optname = prefix + cls.PATH_MATCH_LIST_OPTNAME
        if path_match_list_optname in app_conf:
            obj.path_match_list = app_conf[path_match_list_optname]
       
        return obj
        
    def __call__(self, environ, start_response):
        '''Get client cert used in SSL handshake + username passed in HTTP
        Basic Auth and apply client register to verify the request
        '''
        # Apply register only to URL paths in the path match list.  Ignore if
        # no list is set
        if (self.path_match_list is not None and
            environ['PATH_INFO'] not in self.path_match_list):
            return self.app(environ, start_response)
        
        username = HttpBasicAuthMiddleware.parse_credentials(environ)[0]
        environ[self.userid_keyname] = username
        cert = self._parse_cert(environ)
        if (cert is not None and 
            self.is_valid_client_cert(cert) and
            self.in_client_register(cert, username)):
            
            return self.app(environ, start_response)
        else:
            return HTTPUnauthorized()(environ, start_response)
        
    def _parse_cert(self, environ):
        '''Parse client certificate from environ'''
        pem_cert = environ.get(self.ssl_client_cert_keyname)
        
        # Cert may resolve to null or None
        if not pem_cert:
            return None
        
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        return cert

    @classmethod
    def _is_cert_expired(cls, cert):
        '''Check if input certificate has expired
        @param cert: X.509 certificate
        @type cert: OpenSSL.crypto.X509
        @return: true if expired, false otherwise
        @rtype: bool
        '''
        not_after = cert.get_notAfter()
        dt_not_after = datetime.strptime(not_after, cls.X509_DATETIME_FMT)       
        dt_now = datetime.utcnow()
        
        return dt_not_after < dt_now
    
    @classmethod
    def is_valid_client_cert(cls, cert):
        '''Check certificate time validity
        
        TODO: allow verification against CA certs - current assumption is 
        that Apache config performs this task!
        '''
        if not cert:
            return False
        else:
            return not cls._is_cert_expired(cert)
    
    def in_client_register(self, cert, username):
        '''Check client identity against registry'''
        dn_ = self.__class__.cert_dn(cert)
        
        # Parse DN into canonical form for comparison operation
        subject_name = X509SubjectName.from_string(dn_)
        dn = subject_name.serialize()
        if dn not in self.client_register:
            log.info('Client certificate DN %r not found in client register',
                     dn)
            return False
        
        if username not in self.client_register[dn]:
            log.info('No match for user %r and client certificate DN %r '
                     'in client register', username, dn)            
            return False
        
        return True
        
    @staticmethod
    def cert_dn(cert):
        subject = cert.get_subject()
        components = subject.get_components()
        cert_dn = '/'+ '/'.join(['%s=%s' % i for i in components])
        return cert_dn
        
