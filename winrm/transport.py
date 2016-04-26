from __future__ import unicode_literals
from contextlib import contextmanager
import re
import sys
import os
import weakref
is_py2 = sys.version[0] == '2'
if is_py2:
    from urlparse import urlsplit, urlunsplit
else:
    from urllib.parse import urlsplit, urlunsplit

import requests
import requests.auth
import warnings
from requests.hooks import default_hooks
from requests.adapters import HTTPAdapter

HAVE_KERBEROS = False
try:
    from requests_kerberos import HTTPKerberosAuth, REQUIRED, OPTIONAL, DISABLED
    HAVE_KERBEROS = True
except ImportError:
    pass

HAVE_NTLM = False
try:
    from requests_ntlm import HttpNtlmAuth
    HAVE_NTLM = True
except ImportError as ie:
    pass

from winrm.exceptions import BasicAuthDisabledError, InvalidCredentialsError, \
    WinRMError, WinRMOperationTimeoutError

__all__ = ['Transport']

import ssl

class Transport(object):
    
    def __init__(
            self, endpoint, username=None, password=None, realm=None,
            service=None, keytab=None, ca_trust_path=None, cert_pem=None,
            cert_key_pem=None, read_timeout_sec=None, server_cert_validation='validate',
            kerberos_delegation=False,
            auth_method='auto'):
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.realm = realm
        self.service = service
        self.keytab = keytab
        self.ca_trust_path = ca_trust_path
        self.cert_pem = cert_pem
        self.cert_key_pem = cert_key_pem
        self.read_timeout_sec = read_timeout_sec
        self.server_cert_validation = server_cert_validation
        if self.server_cert_validation not in [None, 'validate', 'ignore']:
            raise WinRMError('invalid server_cert_validation mode: %s' % self.server_cert_validation)

        self.kerberos_delegation = kerberos_delegation

        self.auth_method = auth_method
        self.default_headers = {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'User-Agent': 'Python WinRM client',
        }
        self.session = None

    def build_session(self):
        if self.server_cert_validation == 'ignore':
            # if we're explicitly ignoring validation, try to suppress requests' vendored urllib3 InsecureRequestWarning
            try:
                from requests.packages.urllib3.exceptions import InsecureRequestWarning
                warnings.simplefilter('ignore', category=InsecureRequestWarning)
            except:
                # oh well, we tried...
                pass

        session = requests.Session()

        session.verify = self.server_cert_validation == 'validate'

        # configure proxies from HTTP/HTTPS_PROXY envvars
        session.trust_env = True
        settings = session.merge_environment_settings(url=self.endpoint, proxies={}, stream=None,
                                                      verify=None, cert=None)

        # we're only applying proxies from env, other settings are ignored
        session.proxies = settings['proxies']

        if self.auth_method == 'kerberos':
            if not HAVE_KERBEROS:
                raise WinRMError("requested auth method is kerberos, but requests_kerberos is not installed")
            # TODO: do argspec sniffing on extensions to ensure we're not setting bogus kwargs on older versions
            session.auth = HTTPKerberosAuth(mutual_authentication=REQUIRED, delegate=self.kerberos_delegation,
                                            force_preemptive=True, principal=self.username, realm_override=self.realm)
        elif self.auth_method in ['certificate','ssl']:
            if self.auth_method == 'ssl' and not self.cert_pem and not self.cert_key_pem:
                # 'ssl' was overloaded for HTTPS with optional certificate auth,
                # fall back to basic auth if no cert specified
                session.auth = requests.auth.HTTPBasicAuth(username=self.username, password=self.password)
            else:
                # client cert auth, validate accordingly
                if not self.cert_pem or not self.cert_key_pem:
                    raise InvalidCredentialsError("both cert_pem and cert_key_pem must be specified for cert auth")
                if not os.path.exists(self.cert_pem):
                    raise InvalidCredentialsError("cert_pem file not found (%s)" % self.cert_pem)
                if not os.path.exists(self.cert_key_pem):
                    raise InvalidCredentialsError("cert_key_pem file not found (%s)" % self.cert_key_pem)

                session.cert = (self.cert_pem, self.cert_key_pem)
                session.headers['Authorization'] = \
                    "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"
        elif self.auth_method == 'ntlm':
            if not HAVE_NTLM:
                raise WinRMError("requested auth method is ntlm, but requests_ntlm is not installed")
            if self.password is None:
                raise InvalidCredentialsError("auth method ntlm requires a password")
            session.auth = HttpNtlmAuth(username=self.username, password=self.password)
        # TODO: ssl is not exactly right here- should really be client_cert
        elif self.auth_method in ['basic','plaintext']:
            session.auth = requests.auth.HTTPBasicAuth(username=self.username, password=self.password)

        else:
            raise WinRMError("unsupported auth method: %s" % self.auth_method)

        session.headers.update(self.default_headers)

        return session

    def send_message(self, message):
        # TODO support kerberos session with message encryption

        if not self.session:
            self.session = self.build_session()

        # urllib3 fails on SSL retries with unicode buffers- must send it a byte string
        # see https://github.com/shazow/urllib3/issues/717
        if message is unicode:
            message = message.encode('utf-8')

        request = requests.Request('POST', self.endpoint, data=message)
        prepared_request = self.session.prepare_request(request)

        try:
            response = self.session.send(prepared_request, timeout=self.read_timeout_sec)
            response_text = response.text
            response.raise_for_status()
            return response_text
        except requests.HTTPError as ex:
            if ex.response.status_code == 401:
                raise InvalidCredentialsError("the specified credentials were rejected by the server")
            if ex.response.content:
                response_text = ex.response.content
            else:
                response_text = ''
            # Per http://msdn.microsoft.com/en-us/library/cc251676.aspx rule 3,
            # should handle this 500 error and retry receiving command output.
            if 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive' in message and 'Code="2150858793"' in response_text:
                raise WinRMOperationTimeoutError()

            error_message = 'Bad HTTP response returned from server. Code {0}'.format(ex.response.status_code)

            raise WinRMError('http', error_message)
