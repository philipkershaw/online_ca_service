'''
Created on Oct 2, 2012

@author: philipkershaw
'''
from abc import ABCMeta, abstractmethod


class OnlineCaInterface(object):
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def issue_cert(self, csr, environ):
        '''Issue a certificate from Certificate Signing Request passed
        
        @param csr: Certificate Signing Request
        @type csr: OpenSSL.crypto.X509Req
        @param environ: WSGI environ dictionary
        @type environ: dict-like object
        @return: signed certificate
        @rtype: OpenSSL.crypto.X509
        '''
        
    @abstractmethod
    def get_trustroots(self, environ):
        '''Return CA trust roots (i.e. CA certificates and any signing policy
        files) need to trust this online CA'''