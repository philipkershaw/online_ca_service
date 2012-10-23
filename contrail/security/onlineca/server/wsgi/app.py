"""Online Certificate Authority WSGI Application
 
Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
from paste.httpexceptions import HTTPNotFound

from contrail.security.onlineca.server.wsgi.middleware import OnlineCaMiddleware
from contrail.security.onlineca.server.wsgi.client_register import \
                                                    ClientRegisterMiddleware

        
class OnlineCaApp(object):
    """HTTP interface to OnlineCa logon and get trsut roots.  This interfaces 
    creates a OnlineCa client instance with a HTTP Basic Auth based web service 
    interface to pass username/passphrase for OnlineCa logon calls.  
    
    This WSGI must be run over HTTPS to ensure confidentiality of 
    username/passphrase credentials.  PKI based verification of requests
    should be done out of band of this app e.g. in other filter middleware or
    Apache SSL configuration.
    """
    DEFAULT_PARAM_PREFIX = OnlineCaMiddleware.DEFAULT_PARAM_PREFIX
    
    @classmethod
    def app_factory(cls, global_conf, prefix=DEFAULT_PARAM_PREFIX, **app_conf): 
        """Function following Paste app factory signature
        
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        # This app              
        _app = cls()
                
        # Online CA Middleware 
        app = OnlineCaMiddleware.filter_app_factory(_app, 
                                                    global_conf, 
                                                    prefix=prefix,
                                                    **app_conf)
                
        return app
    
    def __call__(self, environ, start_response):
        """Catch case where request path doesn't match mount point for app"""
#        status = response = '404 Not Found'
#        start_response(status,
#                       [('Content-type', 'text/plain'),
#                        ('Content-length', str(len(response)))])
#        return [response]
        raise HTTPNotFound()
        

class OnlineCaWithClientRegisterApp(OnlineCaApp):
    '''Include client register middleware to enable filtering of clients
    based on client SSL cert DN
    '''
    CLIENT_REGISTER_OPT_PREFIX = \
        ClientRegisterMiddleware.CLIENT_REGISTER_OPT_PREFIX
    
    @classmethod
    def app_factory(cls, global_conf, prefix=OnlineCaApp.DEFAULT_PARAM_PREFIX, 
                    client_register_mware_prefix=CLIENT_REGISTER_OPT_PREFIX, 
                    **app_conf): 
        """Function following Paste app factory signature
        
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type prefix: basestring
        @param prefix: prefix for client register configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        # This app              
        onlineca_app = cls()
                
        # Online CA Middleware 
        onlineca_mware = OnlineCaMiddleware.filter_app_factory(onlineca_app, 
                                                               global_conf, 
                                                               prefix=prefix,
                                                               **app_conf)
        
        clnt_reg_mware = ClientRegisterMiddleware.filter_app_factory(
            onlineca_mware, 
            global_conf, 
            client_register_mware_prefix=client_register_mware_prefix,
            **app_conf)
           
        return clnt_reg_mware
