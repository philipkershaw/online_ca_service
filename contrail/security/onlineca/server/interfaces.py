"""
Class Factory and module import utility

Contrail project
"""
__author__ = "Philip Kershaw"
__date__ = "02/10/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from abc import ABCMeta, abstractmethod


class OnlineCaInterface(object):
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def issue_certificate(self, csr, subject_name, environ):
        '''Issue a certificate from Certificate Signing Request passed
        
        @param csr: Certificate Signing Request
        @type csr: OpenSSL.crypto.X509Req
        @param subject_name: set alternate subject name to one specified in the
        certificate request.  If None, use the subject name in the certificate
        request.
        @type subject_name: OpenSSL.crypto.X509Name or None
        @param environ: WSGI environ dictionary
        @type environ: dict-like object
        @return: signed certificate
        @rtype: OpenSSL.crypto.X509
        '''
