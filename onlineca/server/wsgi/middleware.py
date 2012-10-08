"""MyProxy Web Service WSGI middleware - exposes MyProxy logon and get trust
roots as web service methods
 
NERC MashMyData Project
"""
__author__ = "P J Kershaw"
__date__ = "24/05/10"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import os
import base64

from webob import Request
from paste.httpexceptions import HTTPMethodNotAllowed, HTTPBadRequest
from OpenSSL import crypto

from onlineca.server.interfaces import OnlineCaInterface
from onlineca.server.factory import call_module_object


class OnlineCaMiddlewareError(Exception):
    """Errors related to the MyProxy Web Service middleware"""


class OnlineCaMiddleware(object):
    """Web service interface for issuing certificates and providing CA trust 
    roots
    
    @cvar CA_CLASS_FACTORY_OPTNAME: config file option name for Python path to function 
    or class constructor to make a CA instance.  CA instance must implement CA 
    interface class as defined in the interfaces module - 
    onlineca.server.interfaces import OnlineCaInterface
    @type CA_CLASS_FACTORY_OPTNAME: string
    
    @cvar DEFAULT_CA_CLASS_FACTORY: default value for the key name in 
    WSGI environ dict to assign to the Logon function created by this
    middleware
    @type DEFAULT_CA_CLASS_FACTORY: string
    
    @cvar CERT_REQ_POST_PARAM_KEYNAME: HTTP POST field name for the 
    certificate request posted in logon calls
    @type CERT_REQ_POST_PARAM_KEYNAME: string
    
    @ivar ISSUE_CERT_URIPATH_OPTNAME: ini file option name for issue cert URI
    path parameter
    @type ISSUE_CERT_URIPATH_OPTNAME: string
    
    @ivar DEFAULT_ISSUE_CERT_URIPATH: URI sub-path for issue cert call
    @type DEFAULT_ISSUE_CERT_URIPATH: string
    
    @ivar TRUSTROOTS_URIPATH_OPTNAME: ini file option name for trustroots URI
    path parameter
    @type TRUSTROOTS_URIPATH_OPTNAME: string
    
    @ivar DEFAULT_TRUSTROOTS_URIPATH: URI sub-path for get trustroots call
    @type DEFAULT_TRUSTROOTS_URIPATH: string
    
    @cvar PARAM_PREFIX: prefix for ini file option names 
    @type PARAM_PREFIX: string
    """
    
    # Options for ini file
    CA_CLASS_FACTORY_OPTNAME = 'ca_class_factory_path'

    # Default environ key names
    DEFAULT_CA_CLASS_FACTORY = 'onlineca.server.impl.CertificateAuthorityImpl'
    
    ISSUE_CERT_URIPATH_OPTNAME = 'issue_cert_uripath'
    DEFAULT_ISSUE_CERT_URIPATH = '/certificate/'
    
    TRUSTROOTS_URIPATH_OPTNAME = 'trustroots_uripath'
    DEFAULT_TRUSTROOTS_URIPATH = '/trustroots/'
    
    CERT_REQ_POST_PARAM_KEYNAME = 'certificate_request'
    
    __slots__ = (
        '_app',
        '__ca',
        '__ca_class_factory_path',
        '__issue_cert_uripath',
        '__trustroots_uripath',
        '__trustroots_dir'
    )
    PARAM_PREFIX = 'onlineca.server.'
    CA_PARAM_PREFIX = CA_CLASS_FACTORY_OPTNAME + '.'
    
    def __init__(self, app):
        '''Create attributes
        
        @type app: function
        @param app: WSGI callable for next application in stack
        '''
        self._app = app
        self.__ca_class_factory_path = None
        self.__issue_cert_uripath = None
        self.__trustroots_uripath = None
        self.__ca = None
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix=PARAM_PREFIX, 
                           **app_conf):
        obj = cls(app)
        obj.parse_config(prefix=prefix, **app_conf)
        
        return obj
     
    def parse_config(self, prefix=PARAM_PREFIX, ca_prefix=CA_PARAM_PREFIX,
                     **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type myProxyClientPrefix: basestring
        @param myProxyClientPrefix: explicit prefix for MyProxyClient class 
        specific configuration items - ignored in this derived method
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        
        # Extract parameters
        cls = self.__class__
        ca_class_factory_path_optname = prefix + cls.CA_CLASS_FACTORY_OPTNAME

        self.ca_class_factory_path = app_conf.get(ca_class_factory_path_optname,
                                                  cls.DEFAULT_CA_CLASS_FACTORY)

        issuecert_uripath_optname = prefix + cls.DEFAULT_ISSUE_CERT_URIPATH       
        self.__issue_cert_uripath = app_conf.get(issuecert_uripath_optname,
                                                 cls.DEFAULT_ISSUE_CERT_URIPATH)
        
        trustroot_uripath_optname = prefix + cls.DEFAULT_TRUSTROOTS_URIPATH
        self.__trustroots_uripath = app_conf.get(trustroot_uripath_optname,
                                                 cls.DEFAULT_TRUSTROOTS_URIPATH)
        
        ca_opt_prefix = prefix + ca_prefix
        ca_opt_offset = len(ca_opt_prefix)
        ca_opt = {}
        for optname, optval in app_conf.items():
            if optname.startswith(ca_opt_prefix):
                ca_optname = optname[ca_opt_offset:]
                ca_opt[ca_optname] = optval
                
        self.instantiate_ca(**ca_opt)
        
    def instantiate_ca(self, **ca_object_kwargs):
        '''Create CA class instance
        @param ca_object_kwargs: keywords to CA class constructor
        '''
        self.__ca = call_module_object(self.ca_class_factory_path, 
                                       object_properties=ca_object_kwargs)
        if not isinstance(self.__ca, OnlineCaInterface):
            raise TypeError('%r CA class factory must return a %r derived '
                            'type' % (self.ca_class_factory_path, 
                                      type(OnlineCaInterface)))
        
    @property
    def ca_class_factory_path(self):
        return self.__ca_class_factory_path

    @ca_class_factory_path.setter
    def ca_class_factory_path(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "ca_class_factory_path"'
                            '; got %r type' % type(value))
            
        self.__ca_class_factory_path = value

    @property
    def issue_cert_uripath(self):
        """Get URI path for get trust roots method
        @rtype: basestring
        @return: path for get trust roots method
        """
        return self.__issue_cert_uripath

    @issue_cert_uripath.setter
    def issue_cert_uripath(self, value):
        """Set URI path for get trust roots method
        @type value: basestring
        @param value: path for get trust roots method
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "path"; got %r' % 
                            type(value))
        
        self.__issue_cert_uripath = value

    @property
    def trustroots_uripath(self):
        """Get URI path for get trust roots method
        @rtype: basestring
        @return: path for get trust roots method
        """
        return self.__trustroots_uripath

    @trustroots_uripath.setter
    def trustroots_uripath(self, value):
        """trust roots path
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "path"; got %r' % 
                            type(value))
        
        self.__trustroots_uripath = value 

    @property
    def trustroots_dir(self):
        """Get trust roots dir
        """
        return self.__trustroots_dir

    @trustroots_dir.setter
    def trustroots_dir(self, value):
        """trust roots dir
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "path"; got %r' % 
                            type(value))
        
        self.__trustroots_dir = value 
                   
    def __call__(self, environ, start_response):
        '''Set MyProxy logon method in environ
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        log.debug("OnlineCaMiddleware.__call__ ...")
        request = Request(environ)
        if request.path_info == self.__issue_cert_uripath:
            response = self._issue_certificate(request)
                   
        elif request.path_info == self.__trustroots_uripath:
            response = self._get_trustroots()
            
        else:              
            return self._app(environ, start_response)
            
        start_response('200 OK',
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/plain')])
        return [response]
            
    def _issue_certificate(self, request):
        '''Issue a new certificate from the Certificate Signing Request passed
        in the POST'd request'''
        
        if request.method != 'POST':
            response = "HTTP Request method not recognised"
            log.error("HTTP Request method %r not recognised", request.method)
            raise HTTPMethodNotAllowed(response, headers=[('Allow', 'POST')])
            
        # Extract cert request and convert to standard string - SSL library
        # will not accept unicode
        cert_req_key = self.__class__.CERT_REQ_POST_PARAM_KEYNAME
        pem_cert_req = str(request.POST.get(cert_req_key))
        if pem_cert_req is None:
            response = ("No %r form variable set in POST message" % 
                        cert_req_key)
            log.error(response)
            raise HTTPBadRequest(response)
    
        log.debug("certificate request = %r", pem_cert_req)
        
        # Expecting PEM encoded request
        try:
            cert_req = crypto.load_certificate_request(crypto.FILETYPE_PEM,
                                                       pem_cert_req)
        except crypto.Error:
            log.error("Error loading input certificate request: %r", 
                      pem_cert_req)
            raise HTTPBadRequest("Error loading input certificate request")
            
        cert = self.__ca.issue_certificate(cert_req)
        return cert

    def _get_trustroots(self, request):
        """Call getTrustRoots method on MyProxyClient instance retrieved from
        environ and format and return a HTTP response
        
        @rtype: basestring
        @return: trust roots base64 encoded and concatenated together
        """
        if request.method != 'POST':
            response = "HTTP Request method not recognised"
            log.error("HTTP Request method %r not recognised", request.method)
            raise HTTPMethodNotAllowed(response)
            
        trust_roots = ''
        for filename in os.listdir(self.trustroots_dir):
            file_content = open(filename).read()            
            trust_roots += "%s=%s\n" % (filename, 
                                        base64.b64encode(file_content))
        
        return trust_roots