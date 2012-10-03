'''
Created on Oct 2, 2012

@author: philipkershaw
'''
from paste.httpexceptions import HTTPNotFound

from onlineca.ws.server.interfaces import OnlineCaInterface
from ca.callout_impl import CertificateAuthorityWithCallout
from ca.impl import CertificateAuthority


class CertificateAuthorityWithCalloutImpl(OnlineCaInterface):
    def __init__(self, *arg, **kwarg):
        self.__ca = CertificateAuthorityWithCallout(*arg, **kwarg)
        
    def issue_cert(self, csr, environ):
        return self.__ca.issue_certificate(csr)
    
    def get_trustroots(self, environ):
        '''TODO: implement get_trustroots'''
        raise HTTPNotFound()


class CertificateAuthorityImpl(OnlineCaInterface):
    def __init__(self, *arg, **kwarg):
        self.__ca = CertificateAuthority(*arg, **kwarg)
        
    def issue_cert(self, csr, environ):
        return self.__ca.issue_certificate(
            csr, 
            (not_before_ndays, not_after_ndays))
        
    def get_trustroots(self, environ):
        '''TODO: implement get_trustroots'''
        raise HTTPNotFound()