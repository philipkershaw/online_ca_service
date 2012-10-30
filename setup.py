#!/usr/bin/env python
"""Distribution Utilities setup program for Contrail CA Server Package

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = """BSD - See LICENSE file in top-level directory"""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages


setup(
    name =            	'ContrailOnlineCAService',
    version =         	'0.1.0',
    description =     	'Certificate Authority Web Service',
    long_description = 	'''\
Provides a simple web service interface to a Certificate Authority.  This is 
suitable for use as a SLCS (Short-Lived Credential Service).

The interface is implemented as a WSGI application which fronts a Certificate
Authority.  The Certificate Authority is implemented with the ``ContrailCA``
package also available from PyPI.

Web service call can be made to request an X.509 certificate.  The web service 
interface is RESTful and uses GET and POST operations.  The service should be 
hosted over HTTPS.  Client authentication is configurable to the required means 
using any WSGI-compatible filters including repoze.who.  An application is 
included which  uses HTTP Basic Auth to pass username/password credentials.  
SSL client-based authentication can also be used.  A client is available with 
the ``ContrailOnlineCAClient`` package also available from PyPI.

The code has been developed for the Contrail Project, http://contrail-project.eu/

Prerequisites
=============
This has been developed and tested for Python 2.6 and 2.7.

Installation
============
Installation can be performed using easy_install or pip.

Configuration
=============
Examples are contained in ``contrail.security.onlineca.server.test``.
''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
#    url =             	'http://proj.badc.rl.ac.uk/ndg/wiki/Security/MyProxyWebService',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['ContrailCA',
                         'PasteScript',
                         'WebOb'],
    extras_require =    {'repoze.who': 'repoze.who'},
    license =           __license__,
    test_suite =        'contrail.securuity.onlineca.server.test',
    packages =          find_packages(),
    package_data =      {
        'contrail.security.onlineca.server.test': [
            'README', '*.cfg', '*.ini', '*.crt', '*.key', '*.pem', 'ca/*.0',
            'ca/*.crt', 'ca/*.key'
        ],
        'contrail.security.onlineca.server.test.repoze_eg': [
            'passwd', '*.ini',
        ],
    },
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe = False
)
