Online CA Web Service
=====================
A simple web service interface to a Certificate Authority.  This is 
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
-------------
This has been developed and tested for Python 2.6 and 2.7.

Installation
------------
Installation can be performed using easy_install or pip.

Configuration
-------------
Examples are contained in ``contrail.security.onlineca.server.test``.
