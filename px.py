"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

from __future__ import print_function

__version__ = "0.4.0"
__progname__ = "px"
__servicename__ = __progname__

import argparse
import base64
import ctypes
import multiprocessing
import os
import platform
import select
import signal
import socket
import sys
import threading
import time
import traceback

try:
    from gooey import Gooey, GooeyParser
except ImportError:
    def Gooey(f, *args, **kwargs):
        return f
    class GooeyArgumentGroup(argparse._ArgumentGroup):
        def add_argument(self, *args, **kwargs):
            _ = kwargs.pop('widget', None)
            _ = kwargs.pop('metavar', None)
            _ = kwargs.pop('gooey_options', None)
            super(GooeyArgumentGroup, self).add_argument(*args, **kwargs)
    class GooeyParser(argparse.ArgumentParser):
        def add_argument(self, *args, **kwargs):
            _ = kwargs.pop('widget', None)
            _ = kwargs.pop('gooey_options', None)
            return super(GooeyParser, self).add_argument(*args, **kwargs)
        def add_argument_group(self, *args, **kwargs):
            _ = kwargs.pop('gooey_options', {})
            group = GooeyArgumentGroup(self, *args, **kwargs)
            self._action_groups.append(group)
            return group

# Print if possible
def pprint(*objs):
    try:
        print(*objs)
    except:
        pass

# Dependencies
try:
    import concurrent.futures
except ImportError:
    pprint("Requires module futures")
    sys.exit()

# Need to catch ValueError on non-Windows as well
# due to https://bugs.python.org/issue16396
try:
    import ctypes.wintypes
except (ImportError, ValueError):
    if platform.system() == 'Windows':
        pprint("Requires module ctypes.wintypes on Windows")
        sys.exit()

try:
    import netaddr
except ImportError:
    pprint("Requires module netaddr")
    sys.exit()

try:
    import psutil
except ImportError:
    pprint("Requires module psutil")
    sys.exit()

try:
    import pywintypes
    import sspi
except ImportError:
    if platform.system() == 'Windows':
        pprint("No SSPI support due to missing modules")
        sys.exit()

try:
    import winkerberos
except ImportError:
    if platform.system() == 'Windows':
        pprint("No support for Kerberos on Windows found")
        sys.exit()

try:
    import gssapi
except ImportError:
    pprint("No support for GSSAPI found")

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    try:
        from ntlm_auth.ntlm import Ntlm
    except ImportError:
        pprint("Requires module ntlm-auth")
        sys.exit()
    # compat wrapper for ntlm_auth < 1.2.0
    # just implements the bare minimum of what we actually use here
    class NtlmContext(object):
        def __init__(self, username, password, domain=None, workstation=None,
                     cbt_data=None, ntlm_compatibility=3):
            self.username = username
            self.password = password
            self.domain = domain
            self.workstation = workstation
            _ = cbt_data
            self._context = Ntlm(ntlm_compatibility)
        def step(self, input_token=None):
            if not input_token:
                msg = \
                    self._context.create_negotiate_message(self.domain,
                                                           self.workstation)
            else:
                self._context.parse_challenge_message(base64.b64encode(input_token))
                msg = \
                    self._context.create_authenticate_message(self.username,
                                                              self.password,
                                                              self.domain,
                                                              self.workstation)
            return base64.b64decode(msg)

try:
    import keyring
    if platform.system() == 'Windows':
        import keyring.backends.Windows
        keyring.set_keyring(keyring.backends.Windows.WinVaultKeyring())
except ImportError:
    pprint("Requires module keyring")
    sys.exit()

try:
    import pypac
except ImportError:
    if platform.system() != 'Windows':
        pprint('Requires module pypac unless running on Windows')
        sys.exit()

# Python 2.x vs 3.x support
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
try:
    import http.server as httpserver
except ImportError:
    import SimpleHTTPServer as httpserver
try:
    import socketserver
except ImportError:
    import SocketServer as socketserver
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
try:
    import winreg
except ImportError:
    try:
        import _winreg as winreg
        os.getppid = psutil.Process().ppid
        PermissionError = WindowsError
    except ImportError:
        if platform.system() == 'Windows':
            pprint('Requires module winreg on Windows')
            sys.exit()

HELP = """Px v%s

An HTTP proxy server to automatically authenticate through an NTLM proxy

Usage:
  %s [FLAGS]
  python px.py [FLAGS]

Actions:
  --save
  Save configuration to px.ini or file specified with --config
    Allows setting up Px config directly from command line
    Values specified on CLI override any values in existing config file
    Values not specified on CLI or config file are set to defaults

  --install
  Add Px to the Windows registry to run on startup

  --uninstall
  Remove Px from the Windows registry

  --quit
  Quit a running instance of Px.exe

Configuration:
  --config=
  Specify config file. Valid file path, default: px.ini in working directory

  --proxy=  --server=  proxy:server= in INI file
  NTLM server(s) to connect through. IP:port, hostname:port
    Multiple proxies can be specified comma separated. Px will iterate through
    and use the one that works. Required field unless --noproxy is defined. If
    remote server is not in noproxy list and proxy is undefined, Px will reject
    the request

  --pac=  proxy:pac=
  PAC file to use to connect
    Use in place of server if PAC file should be loaded from a custom URL or
    file location instead of from Internet Options

  --listen=  proxy:listen=
  IP interface to listen on. Valid IP address, default: 127.0.0.1

  --port=  proxy:port=
  Port to run this proxy. Valid port number, default: 3128

  --gateway  proxy:gateway=
  Allow remote machines to use proxy. 0 or 1, default: 0
    Overrides 'listen' and binds to all interfaces

  --hostonly  proxy:hostonly=
  Allow only local interfaces to use proxy. 0 or 1, default: 0
    Px allows all IP addresses assigned to local interfaces to use the service.
    This allows local apps as well as VM or container apps to use Px when in a
    NAT config. Px does this by listening on all interfaces and overriding the
    allow list.

  --allow=  proxy:allow=
  Allow connection from specific subnets. Comma separated, default: *.*.*.*
    Whitelist which IPs can use the proxy. --hostonly overrides any definitions
    unless --gateway mode is also specified
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --noproxy=  proxy:noproxy=
  Direct connect to specific subnets like a regular proxy. Comma separated
    Skip the NTLM proxy for connections to these subnets
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --useragent=  proxy:useragent=
  Override or send User-Agent header on client's behalf

  --username=  proxy:username=
  Authentication to use when SSPI is unavailable. Format is domain\\username
  Service name "Px" and this username are used to retrieve the password using
  Python keyring. Px only retrieves credentials and storage should be done
  directly in the keyring backend.
    On Windows, Credential Manager is the backed and can be accessed from
    Control Panel > User Accounts > Credential Manager > Windows Credentials.
    Create a generic credential with Px as the network address, this username
    and corresponding password.

  --auth=  proxy:auth=
  Force instead of discovering upstream proxy type
    By default, Px will attempt to discover the upstream proxy type and either
    use pywin32/ntlm-auth for NTLM auth or winkerberos for Kerberos or Negotiate
    auth. This option will force either NTLM, Kerberos or Basic and not query the
    upstream proxy type.

  --workers=  settings:workers=
  Number of parallel workers (processes). Valid integer, default: 4
  Only available on Windows with Python v3.3 or later. Otherwise, the number of
  threads is multiplied by this setting

  --threads=  settings:threads=
  Number of parallel threads per worker (process). Valid integer, default: 5

  --idle=  settings:idle=
  Idle timeout in seconds for HTTP connect sessions. Valid integer, default: 30

  --socktimeout=  settings:socktimeout=
  Timeout in seconds for connections before giving up. Valid float, default: 20

  --proxyreload=  settings:proxyreload=
  Time interval in seconds before refreshing proxy info. Valid int, default: 60
    Proxy info reloaded from a PAC file found via WPAD or AutoConfig URL, or
    manual proxy info defined in Internet Options

  --foreground  settings:foreground=
  Run in foreground when frozen or with pythonw.exe. 0 or 1, default: 0
    Px will attach to the console and write to it even though the prompt is
    available for further commands. CTRL-C in the console will exit Px

  --debug  settings:log=
  Enable debug logging. default: 0
    Logs are written to working directory (Windows) or home directory (other
    platforms) and over-written on startup. A log is automatically created
    if Px crashes for some reason

  --uniqlog
  Generate unique log file names
    Prevents logs from being overwritten on subsequent runs. Also useful if
    running multiple instances of Px""" % (__version__, __progname__)

# Windows version
#  6.1 = Windows 7
#  6.2 = Windows 8
#  6.3 = Windows 8.1
# 10.0 = Windows 10
try:
    WIN_VERSION = float(
        str(sys.getwindowsversion().major) + "." +
        str(sys.getwindowsversion().minor))
except AttributeError:
    pass

# Proxy modes - source of proxy info
MODE_NONE = 0
MODE_CONFIG = 1
MODE_AUTO = 2
MODE_PAC = 3
MODE_MANUAL = 4
MODE_CONFIG_PAC = 5

class State(object):
    allow = netaddr.IPGlob("*.*.*.*")
    config = None
    domain = ""
    exit = False
    hostonly = False
    logger = None
    noproxy = netaddr.IPSet([])
    noproxy_hosts = []
    pac = ""
    proxy_mode = MODE_NONE
    proxy_refresh = None
    proxy_server = []
    proxy_type = {}
    stdout = None
    useragent = ""
    username = ""
    auth = None

    ini = "px.ini"
    max_disconnect = 3
    max_line = 65536 + 1

    # Locks for thread synchronization;
    # multiprocess sync isn't neccessary because State object is only shared by
    # threads but every process has it's own State object
    proxy_type_lock = threading.Lock()
    proxy_mode_lock = threading.Lock()

class Response(object):
    __slots__ = ["code", "length", "headers", "data", "body", "chunked", "close"]

    def __init__(self, code=503):
        self.code = code

        self.length = 0

        self.headers = []
        self.data = None

        self.body = False
        self.chunked = False
        self.close = False

class Log(object):
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
    def close(self):
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        self.file.close()
    def write(self, data):
        try:
            self.file.write(data)
        except:
            pass
        if self.stdout is not None:
            self.stdout.write(data)
        self.flush()
    def flush(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        if self.stdout is not None:
            self.stdout.flush()

def dprint(msg):
    if State.logger is not None:
        # Do locking to avoid mixing the output of different threads as there are
        # two calls to print which could otherwise interleave
        sys.stdout.write(
            multiprocessing.current_process().name + ": " +
            threading.current_thread().name + ": " + str(int(time.time())) +
            ": " + sys._getframe(1).f_code.co_name + ": " + msg + "\n")

def dfile():
    name = multiprocessing.current_process().name
    if "--quit" in sys.argv:
        name = "quit"
    if "--uniqlog" in sys.argv:
        name = "%s-%f" % (name, time.time())
    if platform.system() == 'Windows':
        logdir = os.path.dirname(get_script_path())
    else:
        logdir = os.path.expanduser('~')
    logfile = os.path.join(logdir, "debug-%s.log" % name)
    return logfile

def reopen_stdout():
    clrstr = "\r" + " " * 80 + "\r"
    if State.logger is None:
        State.stdout = sys.stdout
        sys.stdout = open("CONOUT$", "w")
        sys.stdout.write(clrstr)
    else:
        State.stdout = State.logger.stdout
        State.logger.stdout = open("CONOUT$", "w")
        State.logger.stdout.write(clrstr)

def restore_stdout():
    if State.logger is None:
        sys.stdout.close()
        sys.stdout = State.stdout
    else:
        State.logger.stdout.close()
        State.logger.stdout = State.stdout

###
# Auth support

def b64decode(val):
    try:
        return base64.decodebytes(val.encode("utf-8"))
    except AttributeError:
        return base64.decodestring(val)

def b64encode(val):
    try:
        return base64.encodebytes(val.encode("utf-8"))
    except AttributeError:
        return base64.encodestring(val)

class AuthMessageGenerator:
    def __init__(self, proxy_type, proxy_server_address):
        pwd = ""
        if State.username:
            key = State.username
            if State.domain != "":
                key = State.domain + "\\" + State.username
            pwd = keyring.get_password("Px", key)

        if proxy_type == "NTLM":
            if not pwd:
                try:
                    self.ctx = sspi.ClientAuth("NTLM",
                      os.environ.get("USERNAME"), scflags=0)
                    self.get_response = self.get_response_sspi
                except NameError:
                    raise NameError('NTLM auth unavailable without SSPI and password')
            else:
                self.ctx = NtlmContext(State.username, pwd, State.domain,
                                       "", ntlm_compatibility=3)
                self.get_response = self.get_response_ntlm
        elif proxy_type == "BASIC":
            if not State.username:
                dprint("No username configured for Basic authentication")
            elif not pwd:
                dprint("No password configured for Basic authentication")
            else:
                # Colons are forbidden in usernames and passwords for basic auth
                # but since this can happen very easily, we make a special check
                # just for colons so people immediately understand that and don't
                # have to look up other resources.
                if ":" in State.username or ":" in pwd:
                    dprint("Credentials contain invalid colon character")
                else:
                    # Additionally check for invalid control characters as per
                    # RFC5234 Appendix B.1 (section CTL)
                    illegal_control_characters = "".join(
                        chr(i) for i in range(0x20)) + "\u007F"

                    if any(char in State.username or char in pwd
                            for char in illegal_control_characters):
                        dprint("Credentials contain invalid characters: %s" % ", ".join("0x" + "%x" % ord(char) for char in illegal_control_characters))
                    else:
                        # Remove newline appended by base64 function
                        self.ctx = b64encode(
                            "%s:%s" % (State.username, pwd))[:-1].decode()
            self.get_response = self.get_response_basic
        else:
            principal = None
            if pwd:
                if State.domain:
                    principal = (urlparse.quote(State.username) + "@" +
                        urlparse.quote(State.domain) + ":" + urlparse.quote(pwd))
                else:
                    principal = (urlparse.quote(State.username) + ":" +
                        urlparse.quote(pwd))

            try:
                _, self.ctx = winkerberos.authGSSClientInit("HTTP@" +
                    proxy_server_address, principal=principal, gssflags=0,
                    mech_oid=winkerberos.GSS_MECH_OID_SPNEGO)
                self.get_response = self.get_response_wkb
            except NameError:
                try:
                    service = gssapi.Name('HTTP@' + proxy_server_address, gssapi.NameType.hostbased_service)
                    # alternative to suppress canonisation of server address:
                    #service = gssapi.Name('HTTP/' + proxy_server_address, gssapi.NameType.kerberos_principal)
                    dprint('* GSSAPI service ' + str(service))
                    self.ctx = gssapi.SecurityContext(name=service, usage='initiate')
                    self.get_response = self.get_response_gssapi
                except NameError:
                    raise NameError('NEGOTIATE/KERBEROS auth unavailable without either winkerberos or gssapi')

    def get_response_sspi(self, challenge=None):
        dprint("pywin32 SSPI")
        if challenge:
            challenge = b64decode(challenge)
        output_buffer = None
        try:
            error_msg, output_buffer = self.ctx.authorize(challenge)
        except pywintypes.error:
            traceback.print_exc(file=sys.stdout)
            return None

        response_msg = b64encode(output_buffer[0].Buffer)
        response_msg = response_msg.decode("utf-8").replace('\012', '')
        return response_msg

    def get_response_gssapi(self, challenge=None):
        dprint("GSSAPI")
        if challenge:
            dprint("* GSSAPI challenge: " + challenge)
            challenge = base64.b64decode(challenge.encode('ascii'))
        try:
            token = self.ctx.step(token=challenge)
        except gssapi.exceptions.GeneralError as exc:
            # GeneralError should not happen during normal usage
            traceback.print_exc(file=sys.stdout)
            return None
        except gssapi.raw.misc.GSSError as exc:
            msgs = list()
            # Omit "Unspecified GSS failure"
            if exc.maj_code != 851968:
                msgs += exc.get_all_statuses(exc.maj_code, True)
            msgs += exc.get_all_statuses(exc.min_code, False)
            _ = [dprint("GSSAPI authentication failed: " + str(x)) for x in msgs]
            return None
        b64token = base64.b64encode(token).decode('ascii')

        return b64token

    def get_response_wkb(self, challenge=""):
        dprint("winkerberos SSPI")
        try:
            winkerberos.authGSSClientStep(self.ctx, challenge)
            auth_req = winkerberos.authGSSClientResponse(self.ctx)
        except winkerberos.GSSError:
            traceback.print_exc(file=sys.stdout)
            return None

        return auth_req

    def get_response_ntlm(self, challenge=""):
        dprint("ntlm-auth")
        if challenge:
            challenge = b64decode(challenge)
        response_msg = b64encode(self.ctx.step(challenge))
        response_msg = response_msg.decode("utf-8").replace('\012', '')
        return response_msg

    def get_response_basic(self, challenge=""):
        dprint("basic")
        return self.ctx

###
# Proxy handler

class Proxy(httpserver.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Contains the proxy servers responsible for the url this Proxy instance
    # (aka thread) serves
    proxy_servers = []
    proxy_socket = None

    def handle_one_request(self):
        try:
            httpserver.SimpleHTTPRequestHandler.handle_one_request(self)
        except socket.error as e:
            dprint("Socket error: %s" % e)
            if not hasattr(self, "_host_disconnected"):
                self._host_disconnected = 1
                dprint("Host disconnected")
            elif self._host_disconnected < State.max_disconnect:
                self._host_disconnected += 1
                dprint("Host disconnected: %d" % self._host_disconnected)
            else:
                dprint("Closed connection to avoid infinite loop")
                self.close_connection = True

    def address_string(self):
        host, port = self.client_address[:2]
        #return socket.getfqdn(host)
        return host

    def log_message(self, format, *args):
        dprint(format % args)

    def do_socket_connect(self, destination=None):
        # Already connected?
        if self.proxy_socket is not None:
            return True

        dests = list(self.proxy_servers) if destination is None else [
            destination]
        for dest in dests:
            dprint("New connection: " + str(dest))
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                proxy_socket.connect(dest)
                self.proxy_address = dest
                self.proxy_socket = proxy_socket
                break
            except Exception as e:
                dprint("Connect failed: %s" % e)
                # move a non reachable proxy to the end of the proxy list;
                if len(self.proxy_servers) > 1:
                    # append first and then remove, this should ensure thread
                    # safety with manual configurated proxies (in this case
                    # self.proxy_servers references the shared
                    # State.proxy_server)
                    self.proxy_servers.append(dest)
                    self.proxy_servers.remove(dest)

        if self.proxy_socket is not None:
            return True

        return False

    def do_socket(self, xheaders={}, destination=None):
        dprint("Entering")

        # Connect to proxy or destination
        if not self.do_socket_connect(destination):
            return Response(408)

        # No chit chat on SSL
        if destination is not None and self.command == "CONNECT":
            return Response(200)

        cl = 0
        chk = False
        expect = False
        keepalive = False
        ua = False
        cmdstr = "%s %s %s\r\n" % (self.command, self.path, self.request_version)
        self.proxy_socket.sendall(cmdstr.encode("utf-8"))
        dprint(cmdstr.strip())
        for header in self.headers:
            hlower = header.lower()
            if hlower == "user-agent" and State.useragent != "":
                ua = True
                h = "%s: %s\r\n" % (header, State.useragent)
            else:
                h = "%s: %s\r\n" % (header, self.headers[header])

            self.proxy_socket.sendall(h.encode("utf-8"))
            if hlower != "authorization":
                dprint("Sending %s" % h.strip())
            else:
                dprint("Sending %s: sanitized len(%d)" % (
                    header, len(self.headers[header])))

            if hlower == "content-length":
                cl = int(self.headers[header])
            elif (hlower == "expect" and
                    self.headers[header].lower() == "100-continue"):
                expect = True
            elif hlower == "proxy-connection":
                keepalive = True
            elif (hlower == "transfer-encoding" and
                    self.headers[header].lower() == "chunked"):
                dprint("CHUNKED data")
                chk = True

        if not keepalive and self.request_version.lower() == "http/1.0":
            xheaders["Proxy-Connection"] = "keep-alive"

        if not ua and State.useragent != "":
            xheaders["User-Agent"] = State.useragent

        for header in xheaders:
            h = ("%s: %s\r\n" % (header, xheaders[header])).encode("utf-8")
            self.proxy_socket.sendall(h)
            if header.lower() != "proxy-authorization":
                dprint("Sending extra %s" % h.strip())
            else:
                dprint("Sending extra %s: sanitized len(%d)" % (
                    header, len(xheaders[header])))
        self.proxy_socket.sendall(b"\r\n")

        if self.command in ["POST", "PUT", "PATCH"]:
            if not hasattr(self, "body"):
                dprint("Getting body for POST/PUT/PATCH")
                if cl:
                    self.body = self.rfile.read(cl)
                else:
                    self.body = self.rfile.read()

            dprint("Sending body for POST/PUT/PATCH: %d = %d" % (
                cl or -1, len(self.body)))
            self.proxy_socket.sendall(self.body)

        self.proxy_fp = self.proxy_socket.makefile("rb")

        resp = Response()

        if self.command != "HEAD":
            resp.body = True

        # Response code
        for i in range(2):
            dprint("Reading response code")
            line = self.proxy_fp.readline(State.max_line)
            if line == b"\r\n":
                line = self.proxy_fp.readline(State.max_line)
            try:
                resp.code = int(line.split()[1])
            except (ValueError, IndexError):
                dprint("Bad response %s" % line)
                if line == b"":
                    dprint("Client closed connection")
                    return Response(444)
            if (b"connection established" in line.lower() or
                    resp.code == 204 or resp.code == 304):
                resp.body = False
            dprint("Response code: %d " % resp.code + str(resp.body))

            # Get response again if 100-Continue
            if not (expect and resp.code == 100):
                break

        # Headers
        dprint("Reading response headers")
        while not State.exit:
            line = self.proxy_fp.readline(State.max_line).decode("utf-8")
            if line == b"":
                if self.proxy_socket:
                    self.proxy_socket.shutdown(socket.SHUT_WR)
                    self.proxy_socket.close()
                    self.proxy_socket = None
                dprint("Proxy closed connection: %s" % resp.code)
                return Response(444)
            if line == "\r\n":
                break
            nv = line.split(":", 1)
            if len(nv) != 2:
                dprint("Bad header =>%s<=" % line)
                continue
            name = nv[0].strip()
            value = nv[1].strip()
            resp.headers.append((name, value))
            if name.lower() != "proxy-authenticate":
                dprint("Received %s: %s" % (name, value))
            else:
                dprint("Received %s: sanitized (%d)" % (name, len(value)))

            if name.lower() == "content-length":
                resp.length = int(value)
                if not resp.length:
                    resp.body = False
            elif (name.lower() == "transfer-encoding" and
                    value.lower() == "chunked"):
                resp.chunked = True
                resp.body = True
            elif (name.lower() in ["proxy-connection", "connection"] and
                    value.lower() == "close"):
                resp.close = True

        return resp

    def do_proxy_type(self):
        # Connect to proxy
        if not hasattr(self, "proxy_address"):
            if not self.do_socket_connect():
                return Response(408), None

        State.proxy_type_lock.acquire()
        try:
            # Read State.proxy_type only once and use value for function return
            # if it is not None; State.proxy_type should only be read here to
            # avoid getting None after successfully identifying the proxy type
            # if another thread clears it with load_proxy
            proxy_type = State.proxy_type.get(self.proxy_address, State.auth)
            if proxy_type is None:
                # New proxy, don't know type yet
                dprint("Searching proxy type")
                resp = self.do_socket()

                proxy_auth = ""
                for header in resp.headers:
                    if header[0].lower() == "proxy-authenticate":
                        proxy_auth += header[1] + " "

                for auth in proxy_auth.split():
                    auth = auth.upper()
                    if auth in ["NTLM", "KERBEROS", "NEGOTIATE", "BASIC"]:
                        proxy_type = auth
                        break

                if proxy_type is not None:
                    # Writing State.proxy_type only once but use local variable
                    # as return value to avoid losing the query result (for the
                    # current request) by clearing State.proxy_type in load_proxy
                    State.proxy_type[self.proxy_address] = proxy_type

                dprint("Auth mechanisms: " + proxy_auth)
                dprint("Selected: " + str(self.proxy_address) + ": " +
                    str(proxy_type))

                return resp, proxy_type

            return Response(407), proxy_type
        finally:
            State.proxy_type_lock.release()

    def do_transaction(self):
        dprint("Entering")

        ipport = self.get_destination()
        if ipport not in [False, True]:
            dprint("Skipping auth proxying")
            resp = self.do_socket(destination=ipport)
        elif ipport:
            # Get proxy type directly from do_proxy_type instead by accessing
            # State.proxy_type do avoid a race condition with clearing
            # State.proxy_type in load_proxy which sometimes led to a proxy type
            # of None (clearing State.proxy_type in one thread was done after
            # another thread's do_proxy_type but before accessing
            # State.proxy_type in the second thread)
            resp, proxy_type = self.do_proxy_type()
            if resp.code == 407:
                # Unknown auth mechanism
                if proxy_type is None:
                    dprint("Unknown auth mechanism expected")
                    return resp

                # Generate auth message
                try:
                    ntlm = AuthMessageGenerator(proxy_type, self.proxy_address[0])
                except NameError as exc:
                    dprint(str(exc))
                    return resp

                ntlm_resp = ntlm.get_response()
                if ntlm_resp is None:
                    dprint("Bad auth response")
                    return Response(503)

                self.fwd_data(resp, flush=True)

                hconnection = ""
                for i in ["connection", "Connection"]:
                    if i in self.headers:
                        hconnection = self.headers[i]
                        del self.headers[i]
                        dprint("Remove header %s: %s" % (i, hconnection))

                # Send auth message
                resp = self.do_socket({
                    "Proxy-Authorization": "%s %s" % (proxy_type, ntlm_resp),
                    "Proxy-Connection": "Keep-Alive"
                })
                if resp.code == 407:
                    dprint("Auth required")
                    ntlm_challenge = ""
                    for header in resp.headers:
                        if (header[0].lower() == "proxy-authenticate" and
                                proxy_type in header[1].upper()):
                            h = header[1].split()
                            if len(h) == 2:
                                ntlm_challenge = h[1]
                                break

                    if ntlm_challenge:
                        dprint("Challenged")
                        ntlm_resp = ntlm.get_response(ntlm_challenge)
                        if ntlm_resp is None:
                            dprint("Bad auth response")
                            return Response(503)

                        self.fwd_data(resp, flush=True)

                        if hconnection != "":
                            self.headers["Connection"] = hconnection
                            dprint("Restore header Connection: " + hconnection)

                        # Reply to challenge
                        resp = self.do_socket({
                            "Proxy-Authorization": "%s %s" % (
                                proxy_type, ntlm_resp)
                        })
                    else:
                        dprint("Didn't get challenge, auth didn't work")
                else:
                    dprint("No auth required cached")
            else:
                dprint("No auth required")
        else:
            dprint("No proxy server specified and not in noproxy list")
            return Response(501)

        return resp

    def do_HEAD(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PAC(self):
        resp = Response(404)
        if State.proxy_mode in [MODE_PAC, MODE_CONFIG_PAC]:
            pac = State.pac
            if "file://" in State.pac:
                pac = file_url_to_local_path(State.pac)
            dprint(pac)
            try:
                resp.code = 200
                with open(pac) as p:
                    resp.data = p.read().encode("utf-8")
                    resp.body = True
                resp.headers = [
                    ("Content-Length", len(resp.data)),
                    ("Content-Type", "application/x-ns-proxy-autoconfig")
                ]
            except:
                traceback.print_exc(file=sys.stdout)

        return resp

    def do_GET(self):
        dprint("Entering")

        dprint("Path = " + self.path)
        if "/PxPACFile.pac" in self.path:
            resp = self.do_PAC()
        else:
            resp = self.do_transaction()

        if resp.code >= 400:
            dprint("Error %d" % resp.code)

        self.fwd_resp(resp)

        dprint("Done")

    def do_POST(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PUT(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_DELETE(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PATCH(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_CONNECT(self):
        dprint("Entering")

        for i in ["connection", "Connection"]:
            if i in self.headers:
                del self.headers[i]
                dprint("Remove header " + i)

        cl = 0
        cs = 0
        resp = self.do_transaction()
        if resp.code >= 400:
            dprint("Error %d" % resp.code)
            self.fwd_resp(resp)
        else:
            # Proxy connection may be already closed due to header
            # (Proxy-)Connection: close received from proxy -> forward this to
            # the client
            if self.proxy_socket is None:
                dprint("Proxy connection closed")
                self.send_response(200, "True")
                self.send_header("Proxy-Connection", "close")
                self.end_headers()
            else:
                dprint("Tunneling through proxy")
                self.send_response(200, "Connection established")
                self.send_header("Proxy-Agent", self.version_string())
                self.end_headers()

                # sockets will be removed from these lists, when they are
                # detected as closed by remote host; wlist contains sockets
                # only when data has to be written
                rlist = [self.connection, self.proxy_socket]
                wlist = []

                # data to be written to client connection and proxy socket
                cdata = []
                sdata = []
                idle = State.config.getint("settings", "idle")
                max_idle = time.time() + idle
                while not State.exit and (rlist or wlist):
                    (ins, outs, exs) = select.select(rlist, wlist, rlist, idle)
                    if exs:
                        break
                    if ins:
                        for i in ins:
                            if i is self.proxy_socket:
                                out = self.connection
                                wdata = cdata
                                source = "proxy"
                            else:
                                out = self.proxy_socket
                                wdata = sdata
                                source = "client"

                            data = i.recv(4096)
                            if data:
                                cl += len(data)
                                # Prepare data to send it later in outs section
                                wdata.append(data)
                                if out not in outs:
                                    outs.append(out)
                                max_idle = time.time() + idle
                            else:
                                # No data means connection closed by remote host
                                dprint("Connection closed by %s" % source)
                                # Because tunnel is closed on one end there is
                                # no need to read from both ends
                                del rlist[:]
                                # Do not write anymore to the closed end
                                if i in wlist:
                                    wlist.remove(i)
                                if i in outs:
                                    outs.remove(i)
                    if outs:
                        for o in outs:
                            if o is self.proxy_socket:
                                wdata = sdata
                            else:
                                wdata = cdata
                            data = wdata[0]
                            # socket.send() may sending only a part of the data
                            # (as documentation says). To ensure sending all data
                            bsnt = o.send(data)
                            if bsnt > 0:
                                if bsnt < len(data):
                                    # Not all data was sent; store data not
                                    # sent and ensure select() get's it when
                                    # the socket can be written again
                                    wdata[0] = data[bsnt:]
                                    if o not in wlist:
                                        wlist.append(o)
                                else:
                                    wdata.pop(0)
                                    if not data and o in wlist:
                                        wlist.remove(o)
                                cs += bsnt
                            else:
                                dprint("No data sent")
                        max_idle = time.time() + idle
                    if max_idle < time.time():
                        # No data in timeout seconds
                        dprint("Proxy connection timeout")
                        break

        # After serving the proxy tunnel it could not be used for samething else.
        # A proxy doesn't really know, when a proxy tunnnel isn't needed any
        # more (there is no content length for data). So servings will be ended
        # either after timeout seconds without data transfer or when at least
        # one side closes the connection. Close both proxy and client
        # connection if still open.
        if self.proxy_socket is not None:
            dprint("Cleanup proxy connection")
            self.proxy_socket.shutdown(socket.SHUT_WR)
            self.proxy_socket.close()
            self.proxy_socket = None
        self.close_connection = True

        dprint("%d bytes read, %d bytes written" % (cl, cs))

        dprint("Done")

    def fwd_data(self, resp, flush=False):
        cl = resp.length
        dprint("Reading response data")
        if resp.body:
            if cl:
                dprint("Content length %d" % cl)
                while cl > 0:
                    if cl > 4096:
                        l = 4096
                        cl -= l
                    else:
                        l = cl
                        cl = 0
                    d = self.proxy_fp.read(l)
                    if not flush:
                        self.wfile.write(d)
            elif resp.chunked:
                dprint("Chunked encoding")
                while not State.exit:
                    line = self.proxy_fp.readline(State.max_line)
                    if not flush:
                        self.wfile.write(line)
                    line = line.decode("utf-8").strip()
                    if not len(line):
                        dprint("Blank chunk size")
                        break
                    else:
                        try:
                            csize = int(line, 16) + 2
                            dprint("Chunk of size %d" % csize)
                        except ValueError:
                            dprint("Bad chunk size '%s'" % line)
                            continue
                    d = self.proxy_fp.read(csize)
                    if not flush:
                        self.wfile.write(d)
                    if csize == 2:
                        dprint("No more chunks")
                        break
                    if len(d) < csize:
                        dprint("Chunk size doesn't match data")
                        break
            elif resp.data is not None:
                dprint("Sending data string")
                if not flush:
                    self.wfile.write(resp.data)
            else:
                dprint("Not sure how much")
                while not State.exit:
                    time.sleep(0.1)
                    d = self.proxy_fp.read(1024)
                    if not flush:
                        self.wfile.write(d)
                    if len(d) < 1024:
                        break

        if resp.close and self.proxy_socket:
            dprint("Close proxy connection per header")
            self.proxy_socket.close()
            self.proxy_socket = None

    def fwd_resp(self, resp):
        dprint("Entering")
        self.send_response(resp.code)

        for header in resp.headers:
            dprint("Returning %s: %s" % (header[0], header[1]))
            self.send_header(header[0], header[1])

        self.end_headers()

        self.fwd_data(resp)

        dprint("Done")

    def get_destination(self):
        netloc = self.path
        path = "/"
        if self.command != "CONNECT":
            parse = urlparse.urlparse(self.path, allow_fragments=False)
            if parse.netloc:
                netloc = parse.netloc
            if ":" not in netloc:
                port = parse.port
                if not port:
                    if parse.scheme == "http":
                        port = 80
                    elif parse.scheme == "https":
                        port = 443
                    elif parse.scheme == "ftp":
                        port = 21
                netloc = netloc + ":" + str(port)

            path = parse.path or "/"
            if parse.params:
                path = path + ";" + parse.params
            if parse.query:
                path = path + "?" + parse.query
        dprint(netloc)

        # Check destination for noproxy first, before doing any expensive stuff
        # possibly involving connections
        if State.noproxy.size:
            addr = []
            spl = netloc.split(":", 1)
            try:
                addr = socket.getaddrinfo(spl[0], int(spl[1]))
            except socket.gaierror:
                # Couldn't resolve, let parent proxy try, #18
                dprint("Couldn't resolve host")
            if len(addr) and len(addr[0]) == 5:
                ipport = addr[0][4]
                dprint("%s => %s + %s" % (self.path, ipport, path))

                if ipport[0] in State.noproxy:
                    dprint("Direct connection from noproxy configuration")
                    self.path = path
                    return ipport

        # Get proxy mode and servers straight from load_proxy to avoid
        # threading issues
        (proxy_mode, self.proxy_servers) = load_proxy()
        if proxy_mode in [MODE_AUTO, MODE_PAC, MODE_CONFIG_PAC]:
            proxy_str = find_proxy_for_url(
                ("https://" if "://" not in self.path else "") + self.path)
            if proxy_str == "DIRECT":
                ipport = netloc.split(":")
                ipport[1] = int(ipport[1])
                dprint("Direct connection from PAC")
                self.path = path
                return tuple(ipport)

            if proxy_str:
                dprint("Proxy from PAC = " + str(proxy_str))
                # parse_proxy does not modify State.proxy_server any more,
                # it returns the proxy server tuples instead, because proxy_str
                # contains only the proxy servers for URL served by this thread
                self.proxy_servers = parse_proxy(proxy_str)

        return True if self.proxy_servers else False

###
# Multi-processing and multi-threading

def get_host_ips():
    localips = [ip[4][0] for ip in socket.getaddrinfo(
        socket.gethostname(), 80, socket.AF_INET)]
    localips.insert(0, "127.0.0.1")

    return localips

class PoolMixIn(socketserver.ThreadingMixIn):
    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

    def verify_request(self, request, client_address):
        dprint("Client address: %s" % client_address[0])
        if client_address[0] in State.allow:
            return True

        if State.hostonly and client_address[0] in get_host_ips():
            dprint("Host-only IP allowed")
            return True

        dprint("Client not allowed: %s" % client_address[0])
        return False

class ThreadedTCPServer(PoolMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass,
            bind_and_activate=True):
        socketserver.TCPServer.__init__(self, server_address,
            RequestHandlerClass, bind_and_activate)

        try:
            # Workaround bad thread naming code in Python 3.6+, fixed in master
            self.pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=State.config.getint("settings", "threads"),
                thread_name_prefix="Thread")
        except:
            self.pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=State.config.getint("settings", "threads"))

def print_banner():
    pprint("Serving at %s:%d proc %s" % (
        State.config.get("proxy", "listen").strip(),
        State.config.getint("proxy", "port"),
        multiprocessing.current_process().name)
    )

    if getattr(sys, "frozen", False) != False or "pythonw.exe" in sys.executable:
        if State.config.getint("settings", "foreground") == 0:
            detach_console()

    for section in State.config.sections():
        for option in State.config.options(section):
            dprint(section + ":" + option + " = " + State.config.get(
                section, option))

def serve_forever(httpd):
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        dprint("Exiting")
        State.exit = True

    httpd.shutdown()

def start_worker(pipeout):
    parse_config()
    httpd = ThreadedTCPServer((
        State.config.get("proxy", "listen").strip(),
        State.config.getint("proxy", "port")), Proxy, bind_and_activate=False)
    mainsock = socket.fromshare(pipeout.recv())
    httpd.socket = mainsock

    print_banner()

    serve_forever(httpd)

def run_pool():
    workers = State.config.getint("settings", "workers")

    if not hasattr(socket, "fromshare"):
        threads = State.config.getint("settings", "threads")
        State.config.set("settings", "threads", str(workers*threads))
        dprint("Platform lacks required features for multi-process support")
        dprint("Adjusted thread pool from %d to %d instead" %
               (threads, State.config.getint("settings", "threads")))

    try:
        httpd = ThreadedTCPServer((State.config.get("proxy", "listen").strip(),
                                   State.config.getint("proxy", "port")), Proxy)
    except OSError as exc:
        if "attempt was made" in str(exc):
            print("Px failed to start - port in use")
        else:
            pprint(exc)
        return

    mainsock = httpd.socket

    print_banner()

    if hasattr(socket, "fromshare"):
        for i in range(workers-1):
            (pipeout, pipein) = multiprocessing.Pipe()
            p = multiprocessing.Process(target=start_worker, args=(pipeout,))
            p.daemon = True
            p.start()
            while p.pid is None:
                time.sleep(1)
            pipein.send(mainsock.share(p.pid))

    serve_forever(httpd)

###
# Proxy detection

try:
    class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
        _fields_ = [("fAutoDetect", ctypes.wintypes.BOOL),
                    # "Automatically detect settings"
                    ("lpszAutoConfigUrl", ctypes.wintypes.LPWSTR),
                    # "Use automatic configuration script, Address"
                    ("lpszProxy", ctypes.wintypes.LPWSTR),
                    # "1.2.3.4:5" if "Use the same proxy server for all protocols",
                    # else advanced
                    # "ftp=1.2.3.4:5;http=1.2.3.4:5;https=1.2.3.4:5;socks=1.2.3.4:5"
                    ("lpszProxyBypass", ctypes.wintypes.LPWSTR),
                    # ";"-separated list
                    # "Bypass proxy server for local addresses" adds "<local>"
                   ]

    class WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
        _fields_ = [("dwFlags", ctypes.wintypes.DWORD),
                    ("dwAutoDetectFlags", ctypes.wintypes.DWORD),
                    ("lpszAutoConfigUrl", ctypes.wintypes.LPCWSTR),
                    ("lpvReserved", ctypes.c_void_p),
                    ("dwReserved", ctypes.wintypes.DWORD),
                    ("fAutoLogonIfChallenged", ctypes.wintypes.BOOL), ]

    class WINHTTP_PROXY_INFO(ctypes.Structure):
        _fields_ = [("dwAccessType", ctypes.wintypes.DWORD),
                    ("lpszProxy", ctypes.wintypes.LPCWSTR),
                    ("lpszProxyBypass", ctypes.wintypes.LPCWSTR), ]
except AttributeError as exc:
    if platform.system() == 'Windows':
        raise exc

# Parameters for WinHttpOpen, http://msdn.microsoft.com/en-us/library/aa384098(VS.85).aspx
WINHTTP_NO_PROXY_NAME = 0
WINHTTP_NO_PROXY_BYPASS = 0
WINHTTP_FLAG_ASYNC = 0x10000000

# dwFlags values
WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002

# dwAutoDetectFlags values
WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

# dwAccessType values
WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4

# Error messages
WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167

def winhttp_find_proxy_for_url(
        url, autodetect=False, pac_url=None, autologon=True):
    # Fix issue #51
    ACCESS_TYPE = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    if WIN_VERSION < 6.3:
        ACCESS_TYPE = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY

    ctypes.windll.winhttp.WinHttpOpen.restype = ctypes.c_void_p
    hInternet = ctypes.windll.winhttp.WinHttpOpen(
        ctypes.wintypes.LPCWSTR("Px"),
        ACCESS_TYPE, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)
    if not hInternet:
        dprint("WinHttpOpen failed: " + str(ctypes.GetLastError()))
        return ""

    autoproxy_options = WINHTTP_AUTOPROXY_OPTIONS()
    if pac_url:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
        autoproxy_options.dwAutoDetectFlags = 0
        autoproxy_options.lpszAutoConfigUrl = pac_url
    elif autodetect:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
        autoproxy_options.dwAutoDetectFlags = (
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A)
        autoproxy_options.lpszAutoConfigUrl = 0
    else:
        return ""
    autoproxy_options.fAutoLogonIfChallenged = autologon

    proxy_info = WINHTTP_PROXY_INFO()

    # Fix issue #43
    ctypes.windll.winhttp.WinHttpGetProxyForUrl.argtypes = [ctypes.c_void_p,
        ctypes.wintypes.LPCWSTR, ctypes.POINTER(WINHTTP_AUTOPROXY_OPTIONS),
        ctypes.POINTER(WINHTTP_PROXY_INFO)]
    ok = ctypes.windll.winhttp.WinHttpGetProxyForUrl(
        hInternet, ctypes.wintypes.LPCWSTR(url),
        ctypes.byref(autoproxy_options), ctypes.byref(proxy_info))
    if not ok:
        error = ctypes.GetLastError()
        dprint("WinHttpGetProxyForUrl error %s" % error)
        if error == WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT:
            dprint("Could not download PAC file, trying DIRECT instead")
            return "DIRECT"
        return ""

    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        # Note: proxy_info.lpszProxyBypass makes no sense here!
        if not proxy_info.lpszProxy:
            dprint('WinHttpGetProxyForUrl named proxy without name')
            return ""
        return proxy_info.lpszProxy.replace(" ", ",").replace(";", ",").replace(
            ",DIRECT", "") # Note: We only see the first!
    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY:
        return "DIRECT"

    # WinHttpCloseHandle()
    dprint("WinHttpGetProxyForUrl accesstype %s" % (proxy_info.dwAccessType,))
    return ""

def pypac_find_proxy_for_url(url, autodetect=False, pac_url=None):
    dprint("Detecting proxy for URL " + str(url))
    dprint("Using PAC URL " + str(pac_url) + ", autodetection " + str(autodetect))
    try:
        with open(pac_url) as f:
            pacfile = pypac.parser.PACFile(f.read())
    except (OSError, TypeError):
        pacfile = pypac.get_pac(url=pac_url, from_dns=autodetect)

    if not pacfile:
        dprint("No PAC file, trying DIRECT instead")
        return "DIRECT"

    parts = urlparse.urlparse(url)
    host = urlparse.unquote(parts.netloc).split(':', 1)[0]
    proxy_info = pacfile.find_proxy_for_url(str(url), host)

    proxies = pypac.parser.parse_pac_value(proxy_info)

    supported_proxies = []
    for x in proxies:
        if x.startswith('http://'):
            supported_proxies.append(x[7:])
        elif x == 'DIRECT':
            supported_proxies.append(x)
        else:
            dprint("Removing unsupported proxy: " + x)

    dprint("Found proxies: " + ','.join(supported_proxies))
    return ','.join(supported_proxies)

def file_url_to_local_path(file_url):
    parts = urlparse.urlparse(file_url)
    path = urlparse.unquote(parts.path)
    if platform.system() != 'Windows':
        return path
    if path.startswith('/') and not path.startswith('//'):
        if len(parts.netloc) == 2 and parts.netloc[1] == ':':
            return parts.netloc + path
        return 'C:' + path
    if len(path) > 2 and path[1] == ':':
        return path

def load_proxy(quiet=False):
    # Return if proxies specified in Px config
    if State.proxy_mode in [MODE_CONFIG, MODE_CONFIG_PAC]:
        return (State.proxy_mode, State.proxy_server)

    # Do locking to avoid updating globally shared State object by multiple
    # threads simultaneously
    State.proxy_mode_lock.acquire()
    try:
        proxy_mode = State.proxy_mode
        proxy_servers = State.proxy_server
        # Check if need to refresh
        if (State.proxy_refresh is not None and
                time.time() - State.proxy_refresh <
                State.config.getint("settings", "proxyreload")):
            if not quiet:
                dprint("Skip proxy refresh")
            return (proxy_mode, proxy_servers)

        # Start with clean proxy mode and server list
        proxy_mode = MODE_NONE
        proxy_servers = []

        try:
            # Get proxy info from Internet Options
            ie_proxy_config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
            ok = ctypes.windll.winhttp.WinHttpGetIEProxyConfigForCurrentUser(
                ctypes.byref(ie_proxy_config))
            if not ok:
                if not quiet:
                    dprint(ctypes.GetLastError())
            else:
                if ie_proxy_config.fAutoDetect:
                    proxy_mode = MODE_AUTO
                elif ie_proxy_config.lpszAutoConfigUrl:
                    State.pac = ie_proxy_config.lpszAutoConfigUrl
                    proxy_mode = MODE_PAC
                    if not quiet:
                        dprint("AutoConfigURL = " + State.pac)
                else:
                    # Manual proxy
                    proxies = []
                    proxies_str = ie_proxy_config.lpszProxy or ""
                    for proxy_str in proxies_str.lower().replace(
                            ' ', ';').split(';'):
                        if '=' in proxy_str:
                            scheme, proxy = proxy_str.split('=', 1)
                            if scheme.strip() != "ftp":
                                proxies.append(proxy)
                        elif proxy_str:
                            proxies.append(proxy_str)
                    if proxies:
                        proxy_servers = parse_proxy(",".join(proxies))
                        proxy_mode = MODE_MANUAL

                    # Proxy exceptions into noproxy
                    bypass_str = ie_proxy_config.lpszProxyBypass or "" # FIXME: Handle "<local>"
                    bypasses = [h.strip() for h in bypass_str.lower().replace(
                        ' ', ';').split(';')]
                    for bypass in bypasses:
                        try:
                            ipns = netaddr.IPGlob(bypass)
                            State.noproxy.add(ipns)
                            if not quiet:
                                dprint("Noproxy += " + bypass)
                        except:
                            State.noproxy_hosts.append(bypass)
                            if not quiet:
                                dprint("Noproxy hostname += " + bypass)
        except (AttributeError, NameError):
            # Non-Windows
            proxy_mode = MODE_AUTO
            proxy_servers = []

        State.proxy_refresh = time.time()
        if not quiet:
            dprint("Proxy mode = " + str(proxy_mode))
        State.proxy_mode = proxy_mode
        State.proxy_server = proxy_servers

        # Clear proxy types on proxy server update
        State.proxy_type = {}

    finally:
        State.proxy_mode_lock.release()

    return (proxy_mode, proxy_servers)

def find_proxy_for_url(url):
    proxy_str = ""
    if State.proxy_mode == MODE_AUTO:
        if platform.system() == 'Windows':
            proxy_str = winhttp_find_proxy_for_url(url, autodetect=True)
        else:
            proxy_str = pypac_find_proxy_for_url(url, autodetect=True)

    elif State.proxy_mode in [MODE_PAC, MODE_CONFIG_PAC]:
        pac = State.pac
        if platform.system() != 'Windows':
            proxy_str = pypac_find_proxy_for_url(url, pac_url=pac)
        else:
            if "file://" in State.pac or not State.pac.startswith("http"):
                host = State.config.get("proxy", "listen") or "localhost"
                port = State.config.getint("proxy", "port")
                pac = "http://%s:%d/PxPACFile.pac" % (host, port)
                dprint("PAC URL is local: " + pac)
            proxy_str = winhttp_find_proxy_for_url(url, pac_url=pac)

    # Handle edge case if the result is a list that starts with DIRECT. Assume
    # everything should be direct as the string DIRECT is tested explicitly in
    # get_destination
    if proxy_str.startswith("DIRECT,"):
        proxy_str = "DIRECT"

    # If the proxy_str it still empty at this point, then there is no proxy
    # configured. Try to do a direct connection.
    if proxy_str == "":
        proxy_str = "DIRECT"

    dprint("Proxy found: " + proxy_str)
    return proxy_str

###
# Parse settings and command line

def parse_proxy(proxystrs):
    if not proxystrs:
        return []

    servers = []
    for proxystr in [i.strip() for i in proxystrs.split(",")]:
        pserver = [i.strip() for i in proxystr.split(":")]
        if len(pserver) == 1:
            pserver.append(80)
        elif len(pserver) == 2:
            try:
                pserver[1] = int(pserver[1])
            except ValueError:
                pprint("Bad proxy server port: " + pserver[1])
                sys.exit()
        else:
            pprint("Bad proxy server definition: " + proxystr)
            sys.exit()

        if tuple(pserver) not in servers:
            servers.append(tuple(pserver))

    return servers

def parse_ip_ranges(iprangesconfig):
    ipranges = netaddr.IPSet([])

    iprangessplit = [i.strip() for i in iprangesconfig.split(",")]
    for iprange in iprangessplit:
        if not iprange:
            continue

        try:
            if "-" in iprange:
                spl = iprange.split("-", 1)
                ipns = netaddr.IPRange(spl[0], spl[1])
            elif "*" in iprange:
                ipns = netaddr.IPGlob(iprange)
            else:
                ipns = netaddr.IPNetwork(iprange)
            ipranges.add(ipns)
        except:
            pprint("Bad IP definition: %s" % iprangesconfig)
            sys.exit()
    return ipranges

def parse_allow(allow):
    State.allow = parse_ip_ranges(allow)

def parse_noproxy(noproxy):
    State.noproxy = parse_ip_ranges(noproxy)

def set_useragent(useragent):
    State.useragent = useragent

def set_username(username):
    ud = username.split("\\")
    if len(ud) == 2:
        State.username = ud[1]
        State.domain = ud[0]
    else:
        State.username = username

def set_pac(pac):
    if pac == "":
        return

    pacproxy = False
    if pac.startswith("http"):
        pacproxy = True

    elif pac.startswith("file"):
        pac = file_url_to_local_path(pac)

    if os.path.exists(pac):
        pacproxy = True

    if pacproxy:
        State.pac = pac
    else:
        pprint("Unsupported PAC location or file not found: %s" % pac)
        sys.exit()

def set_auth(auth):
    if auth.upper() not in ["NTLM", "KERBEROS", "BASIC", "AUTO", ""]:
        pprint("Bad proxy auth type: %s" % auth)
        sys.exit()
    if auth not in ('', 'AUTO'):
        State.auth = auth

def cfg_int_init(section, name, default, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    try:
        val = int(val)
    except ValueError:
        pprint("Invalid integer value for " + section + ":" + name)

    State.config.set(section, name, str(val))

def cfg_float_init(section, name, default, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    try:
        val = float(val)
    except ValueError:
        pprint("Invalid float value for " + section + ":" + name)

    State.config.set(section, name, str(val))

def cfg_str_init(section, name, default, proc=None, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    State.config.set(section, name, val)

    if proc != None:
        proc(val)

def save():
    with open(State.ini, "w") as cfgfile:
        State.config.write(cfgfile)
    pprint("Saved config to " + State.ini + "\n")
    with open(State.ini, "r") as cfgfile:
        sys.stdout.write(cfgfile.read())

    sys.exit()

# Automagic GUI support via Gooey wraps a single function that contains all
# argument parsing. However, in order to pre-seed the GUI with proper defaults
# from the conffile, we need to parse the command-line (at least the part
# dealing with the location of the conffile) before the GUI wrapper is
# invoked. In order to address this problem with minimal code duplication,
# we split up command-line parsing into two functions: In parse_initial(),
# we deal with conffile handling, and all the other arguments that we don't
# want or need to expose in the GUI. From here, we call into parse_config()
# that handles the rest of the arguments, and dynamically apply the GUI
# wrapper to it as required.
def parse_initial():
    parser = argparse.ArgumentParser(prog=__progname__, description='An HTTP proxy server to automatically authenticate through an NTLM proxy', add_help=False)

    parser.add_argument('--config', default='', help='Specify config file. Valid file path, default: px.ini in working directory (user homedir on Linux)')

    actions = parser.add_argument_group('actions')

    actions.add_argument('--save', action='store_true', default=False, help='Save configuration to px.ini or file specified with --config')
    actions.add_argument('--set-password', metavar="USER", help='Query NTLM password for USER and store in keyring')

    if platform.system() == 'Windows':
        actions.add_argument('--install', action='store_true', default=False, help='Add Px to the Windows registry to run on startup')
        actions.add_argument('--uninstall', action='store_true', default=False, help='Remove Px from the Windows registry')
    elif platform.system() == 'Linux':
        actions.add_argument('--install', action='store_true', default=False, help='Add Px to systemd user startup')
        actions.add_argument('--uninstall', action='store_true', default=False, help='Remove Px systemd user startup')
    else:
        pass

    actions.add_argument('--quit', action='store_true', default=False, help='Quit a running instance of Px.exe')

    args, remaining_args = parser.parse_known_args()

    if getattr(args, 'install', False):
        install()
    elif getattr(args, 'uninstall', False):
        uninstall()
    elif getattr(args, 'set_password', ''):
        set_password(args.set_password)
    elif args.quit:
        quit()

    # Load configuration file
    State.config = configparser.ConfigParser()

    if args.config:
        State.ini = args.config
    elif platform.system() == 'Windows':
        State.ini = os.path.join(os.path.dirname(get_script_path()), State.ini)
    else:
        State.ini = os.path.join(os.path.expanduser('~'), State.ini)


    # Special-case Gooey's internal option --ignore-gooey: It means we've
    # been called from the GUI, which gives us a /complete/ set of
    # command-line options as desired by the user. In this case, we don't
    # want to pre-seed defaults from the conffile, but use only what's
    # given on the command-line.
    # For most options, this distinction isn't necessary because the
    # command-line overrides options in the conffile, anyway. However, we
    # do have a couple of boolean options (eg. --hostonly) that can only
    # be activated on the command-line, but there's no way to deactivate
    # a boolean option that is activated in the conffile. This may be ok
    # for CLI use, but it breaks the UX in the GUI case. We can fix the
    # behaviour by skipping the conffile entirely, which makes all boolean
    # options default to False.
    if '--ignore-gooey' not in remaining_args:
        ini_read = State.config.read(State.ini)
        if not args.save and args.config and args.config not in ini_read:
            pprint("Unable to parse config file: " + State.ini)
            sys.exit()

    # [proxy] section
    if "proxy" not in State.config.sections():
        State.config.add_section("proxy")

    cfg_str_init("proxy", "server", "")
    cfg_str_init("proxy", "pac", "", set_pac)
    cfg_int_init("proxy", "port", "3128")
    cfg_str_init("proxy", "listen", "127.0.0.1")
    cfg_str_init("proxy", "allow", "*.*.*.*", parse_allow)
    cfg_int_init("proxy", "gateway", "0")
    cfg_int_init("proxy", "hostonly", "0")
    cfg_str_init("proxy", "noproxy", "", parse_noproxy)
    cfg_str_init("proxy", "useragent", "", set_useragent)
    cfg_str_init("proxy", "username", "", set_username)
    cfg_str_init("proxy", "auth", "", set_auth)

    # [settings] section
    if "settings" not in State.config.sections():
        State.config.add_section("settings")

    cfg_int_init("settings", "workers", "4")
    cfg_int_init("settings", "threads", "5")
    cfg_int_init("settings", "idle", "30")
    cfg_float_init("settings", "socktimeout", "20.0")
    cfg_int_init("settings", "proxyreload", "60")
    cfg_int_init("settings", "foreground", "0")
    cfg_int_init("settings", "log", "0")

    # Only fire up GUI if we've been called without
    # arguments (except --config), and if we stand
    # a chance to actually use a working display.
    if len(remaining_args) == 0 and \
       os.getenv('DISPLAY', '') != '':
        # XXX We'd like to set show_stop_warning=False here, but it seems to
        #     be broken in current Gooey. (Pressing the Stop button doesn't
        #     have any effect at all.)
        return Gooey(parse_config,
                     default_size=(1000, 800),
                     progress_regex=r'^Serving at \w*:(?P<port>\d+) proc MainProcess$',
                     progress_expr="port and 100")(None)

    # Remove Gooey-internal option. This is usually handled by the wrapper, but
    # due to our conditional wrapping, we need to handle it manually.
    try:
        sys.argv.remove('--ignore-gooey')
    except ValueError:
        pass

    # We've suppressed the default help option above (because it would only
    # show the 'initial' arguments). In order to retain '--help' for the
    # non-GUI case, we need to re-add it manually.
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')
    parse_config(parser)

def parse_config(parser=None):
    # parse_initial() calls us with a None arg if we're Gooey-wrapped and need
    # to build an ArgumentParser from scratch for GUI use.
    # In the CLI case (parser != None), we can simply add further arguments to
    # the existing parser. This allows us to obtain the full --help output
    # without duplicating arguments here.
    gui = not bool(parser)
    if gui:
        parser = GooeyParser(prog=__progname__, description='An HTTP proxy server to automatically authenticate through an NTLM proxy')

        # Arguments that need to be available both in parse_initial() and in
        # the GUI. For there, we just go with a bit of duplication.
        parser.add_argument('--config', default=State.ini, widget='FileChooser', gooey_options={'full_width': True}, help='Specify config file. Valid file path, default: px.ini in working directory (user homedir on Linux)')
        parser.add_argument('--save', action='store_true', default=False, help='Save configuration to config file and exit')

    # command-line arguments corresponding to section [proxy] in px.ini
    options = parser.add_argument_group('proxy options')
    options.add_argument('--proxy', '--server', default=State.config.get('proxy', 'server'), help='NTLM server(s) to connect through. (IP:port, hostname:port)')
    options.add_argument('--pac', default=State.config.get('proxy', 'pac'), help='PAC file to use to connect')
    options.add_argument('--listen', default=State.config.get('proxy', 'listen'), help='IP interface to listen on')
    options.add_argument('--port', default=int(State.config.get('proxy', 'port')), type=int, help='Port to run this proxy. Valid port number')
    options.add_argument('--gateway', action='store_true', default=bool(int(State.config.get('proxy', 'gateway'))), help='Allow remote machines to use proxy')
    options.add_argument('--hostonly', action='store_true', default=bool(int(State.config.get('proxy', 'hostonly'))), help='Allow only local interfaces to use proxy')
    options.add_argument('--username', default=State.config.get('proxy', 'username'), help='Authentication to use when SSPI/GSSAPI is unavailable (matching password is retrieved from keyring)')
    options.add_argument('--allow', default=State.config.get('proxy', 'allow'), help='Allow connection from specific subnets (comma-separated list)')
    options.add_argument('--noproxy', default=State.config.get('proxy', 'noproxy'), help='Direct connect to specific subnets like a regular proxy (comma-separated list)')
    options.add_argument('--useragent', default=State.config.get('proxy', 'useragent'), help='Override or send User-Agent header on client\'s behalf')
    options.add_argument('--auth', choices=['NTLM', 'BASIC', 'KERBEROS', 'AUTO'], default=State.config.get('proxy', 'auth'), help='Upstream proxy type')

    # command-line arguments corresponding to section [settings] in px.ini
    settings = parser.add_argument_group('settings')
    settings.add_argument('--workers', default=int(State.config.get('settings', 'workers')), type=int, help='Number of parallel workers (processes)')
    settings.add_argument('--threads', default=int(State.config.get('settings', 'threads')), type=int, help='Number of parallel threads per worker (process)')
    settings.add_argument('--idle', default=int(State.config.get('settings', 'idle')), type=int, help='Idle timeout in seconds for HTTP connect sessions')
    settings.add_argument('--socktimeout', default=float(State.config.get('settings', 'socktimeout')), type=float, help='Timeout in seconds for connections before giving up')
    settings.add_argument('--proxyreload', default=int(State.config.get('settings', 'proxyreload')), type=int, help='Time interval in seconds before refreshing proxy info')
    settings.add_argument('--foreground', action='store_true', default=bool(int(State.config.get('settings', 'foreground'))), help='Run in foreground when frozen or with pythonw.exe')
    settings.add_argument('--debug', '--log', action='store_true', default=bool(int(State.config.get('settings', 'log'))), help='Enable debug logging')
    settings.add_argument('--uniqlog', action='store_true', default=False, help='Generate unique log file names')

    args = parser.parse_args()

    if args.debug:
        State.logger = Log(dfile(), "w")

    if getattr(sys, "frozen", False) != False or "pythonw.exe" in sys.executable:
        attach_console()

    cfg_int_init("settings", "log", "0" if State.logger is None else "1")
    if State.config.get("settings", "log") == "1" and State.logger is None:
        State.logger = Log(dfile(), "w")

    cfg_str_init("proxy", "server", args.proxy, None, True)
    cfg_str_init("proxy", "pac", args.pac, set_pac, True)
    cfg_str_init("proxy", "listen", args.listen, None, True)
    cfg_int_init("proxy", "port", args.port, True)
    cfg_str_init("proxy", "allow", args.allow, parse_allow, True)
    cfg_str_init("proxy", "noproxy", args.noproxy, parse_noproxy, True)
    cfg_str_init("proxy", "useragent", args.useragent, set_useragent, True)
    cfg_str_init("proxy", "username", args.username, set_username, True)
    cfg_str_init("proxy", "auth", args.auth, set_auth, True)

    cfg_int_init("settings", "workers", args.workers, True)
    cfg_int_init("settings", "threads", args.threads, True)
    cfg_int_init("settings", "idle", args.idle, True)
    cfg_int_init("settings", "proxyreload", args.proxyreload, True)
    cfg_int_init("settings", "socktimeout", args.socktimeout, True)
    cfg_int_init("proxy", "gateway", int(args.gateway), True)
    cfg_int_init("proxy", "hostonly", int(args.hostonly), True)
    cfg_int_init("settings", "foreground", int(args.foreground), True)

    ###
    # Dependency propagation

    # If gateway mode
    if State.config.getint("proxy", "gateway") == 1:
        # Listen on all interfaces
        cfg_str_init("proxy", "listen", "", None, True)

    # If hostonly mode
    if State.config.getint("proxy", "hostonly") == 1:
        State.hostonly = True

        # Listen on all interfaces
        cfg_str_init("proxy", "listen", "", None, True)

        # If not gateway mode or gateway with default allow rules
        if (State.config.getint("proxy", "gateway") == 0 or
                (State.config.getint("proxy", "gateway") == 1 and
                 State.config.get("proxy", "allow") in [
                    "*.*.*.*", "0.0.0.0/0"])):
            # Purge allow rules
            cfg_str_init("proxy", "allow", "", parse_allow, True)

    State.proxy_server = parse_proxy(State.config.get("proxy", "server"))

    if args.save:
        save()

    if State.proxy_server:
        State.proxy_mode = MODE_CONFIG
    elif State.pac:
        State.proxy_mode = MODE_CONFIG_PAC
    else:
        load_proxy(quiet=False)

    if State.proxy_mode == MODE_NONE and not State.config.get(
            "proxy", "noproxy"):
        pprint("No proxy server or noproxy list defined")
        sys.exit()

    socket.setdefaulttimeout(State.config.getfloat("settings", "socktimeout"))

###
# Exit related

def quit(force=False):
    count = 0
    mypids = [os.getpid(), os.getppid()]
    for pid in sorted(psutil.pids(), reverse=True):
        if pid in mypids:
            continue

        try:
            p = psutil.Process(pid)
            if p.exe().lower() == sys.executable.lower():
                count += 1
                if force:
                    p.kill()
                else:
                    p.send_signal(signal.CTRL_C_EVENT)
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, SystemError):
            pass
        except:
            traceback.print_exc(file=sys.stdout)

    if count != 0:
        if force:
            sys.stdout.write(".")
        else:
            sys.stdout.write("Quitting Px ..")
            time.sleep(4)
        sys.stdout.flush()
        quit(True)
    else:
        if force:
            pprint(" DONE")
        else:
            pprint("Px is not running")

    sys.exit()

def handle_exceptions(extype, value, tb):
    # Create traceback log
    lst = (traceback.format_tb(tb, None) +
        traceback.format_exception_only(extype, value))
    tracelog = '\nTraceback (most recent call last):\n' + "%-20s%s\n" % (
        "".join(lst[:-1]), lst[-1])

    if State.logger != None:
        pprint(tracelog)
    else:
        sys.stderr.write(tracelog)

        # Save to debug.log
        dbg = open(dfile(), 'w')
        dbg.write(tracelog)
        dbg.close()

###
# Install Px to startup

def get_script_path():
    if getattr(sys, "frozen", False) is False:
        # Script mode
        return os.path.normpath(os.path.join(os.getcwd(), sys.argv[0]))

    # Frozen mode
    return sys.executable

def get_script_cmd():
    spath = get_script_path()
    if os.path.splitext(spath)[1].lower() == ".py":
        return sys.executable + ' "%s"' % spath

    return spath

def check_installed():
    if platform.system() != 'Windows':
        return False

    ret = True
    runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
    try:
        winreg.QueryValueEx(runkey, "Px")
    except:
        ret = False
    winreg.CloseKey(runkey)

    return ret

def install():
    if platform.system() == 'Linux':
        sys.exit(os.system('/bin/systemctl --user enable ' + __servicename__))
    elif platform.system() != 'Windows':
        sys.exit('Install not supported on ' + platform.system())

    if check_installed() is False:
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            winreg.KEY_WRITE)
        winreg.SetValueEx(runkey, "Px", 0, winreg.REG_EXPAND_SZ,
            get_script_cmd())
        winreg.CloseKey(runkey)
        pprint("Px installed successfully")
    else:
        pprint("Px already installed")

    sys.exit()

def uninstall():
    if platform.system() == 'Linux':
        sys.exit(os.system('/bin/systemctl --user disable ' + __servicename__))
    elif platform.system() != 'Windows':
        sys.exit('Uninstall not supported on ' + platform.system())

    if check_installed() is True:
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            winreg.KEY_WRITE)
        winreg.DeleteValue(runkey, "Px")
        winreg.CloseKey(runkey)
        pprint("Px uninstalled successfully")
    else:
        pprint("Px is not installed")

    sys.exit()

def set_password(username):
    if sys.stdin.isatty():
        import getpass
        password = getpass.getpass('Password: ')
    else:
        password = sys.stdin.readline().rstrip()

    if password:
        keyring.set_password('Px', username, password)
        pprint('Password stored in default keyring service Px and user ' + username)
    else:
        pprint('Empty password, skipping...')

    sys.exit()

###
# Attach/detach console

def attach_console():
    if platform.system() != 'Windows':
        return

    if ctypes.windll.kernel32.GetConsoleWindow() != 0:
        dprint("Already attached to a console")
        return

    # Find parent cmd.exe if exists
    pid = os.getpid()
    while True:
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            # No such parent - started without console
            pid = -1
            break

        if os.path.basename(p.name()).lower() in [
                "cmd", "cmd.exe", "powershell", "powershell.exe"]:
            # Found it
            break

        # Search parent
        pid = p.ppid()

    # Not found, started without console
    if pid == -1:
        dprint("No parent console to attach to")
        return

    dprint("Attaching to console " + str(pid))
    if ctypes.windll.kernel32.AttachConsole(pid) == 0:
        dprint("Attach failed with error " +
            str(ctypes.windll.kernel32.GetLastError()))
        return

    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        dprint("Not a console window")
        return

    reopen_stdout()

def detach_console():
    if platform.system() != 'Windows':
        return

    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        return

    restore_stdout()

    if not ctypes.windll.kernel32.FreeConsole():
        dprint("Free console failed with error " +
            str(ctypes.windll.kernel32.GetLastError()))
    else:
        dprint("Freed console successfully")

###
# Startup

def main():
    multiprocessing.freeze_support()
    sys.excepthook = handle_exceptions

    parse_initial()

    run_pool()

if __name__ == "__main__":
    main()
