"""Online Certificate Authority Application - variant secured additional
filter to enable securing of the issue certificate operation with repoze.who
 
Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "14/10/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from contrail.security.onlineca.server.wsgi.app import OnlineCaApp
from contrail.security.onlineca.server.wsgi.repoze_middleware import \
                                                        RepozeWhoUrlMatchFilter


class RepozeSecuredOnlineCaApp(object):
    '''Online CA wrapped with a filter to intercept get certificate requests
    using Repoze.who's HTTP Basic Auth middleware.  RepozeWhoUrlMatchFilter
    merely sets a HTTP 401 Unauthorized response if the the 
    repoze.who.identity key is not set in environ.  The repoze.who middleware
    must configure the appropriate authentication middleware for HTTP
    Basic Auth.  This can be done conveniently with a Paste ini file.
    '''
    @classmethod
    def app_factory(cls, global_conf, prefix=OnlineCaApp.DEFAULT_PARAM_PREFIX, 
                    **app_conf):
        app = OnlineCaApp.app_factory(global_conf, prefix=prefix, **app_conf)
        
        wrapped_app = RepozeWhoUrlMatchFilter(app)
        wrapped_app.urlpath_match_list = [app.issue_cert_uripath]
        
        return wrapped_app