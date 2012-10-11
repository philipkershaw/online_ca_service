'''
Created on Oct 2, 2012

@author: philipkershaw
'''
from onlineca.server.interfaces import OnlineCaInterface
from ca.callout_impl import CertificateAuthorityWithCallout
from ca.impl import CertificateAuthority


class CertificateAuthorityWithCalloutImpl(OnlineCaInterface):
    def __init__(self, *arg, **kwarg):
        self.__ca = CertificateAuthorityWithCallout(*arg, **kwarg)
        
    def issue_certificate(self, csr, subject_name, environ):
        return self.__ca.issue_certificate(csr, subject_name=subject_name)


class CertificateAuthorityImpl(OnlineCaInterface):
    def __init__(self, *arg, **kwarg):
        self.__ca = CertificateAuthority.from_keywords(**kwarg)
        
    def issue_certificate(self, csr, subject_name, environ):
        return self.__ca.issue_certificate(csr, subject_name=subject_name)
