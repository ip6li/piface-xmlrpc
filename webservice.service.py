#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-

# Licenced under conditions of Gnu General Public License version 3

import os, sys, time, atexit
import grp
import pwd
import signal
import logging
import logging.handlers
import inspect
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import threading
import socketserver
import pifacedigitalio

#DEBUG=True
DEBUG=False

lockFileDir='/var/run/webservice'
lockFileName=lockFileDir+'/webservice.server.pid'

cadm_uid = pwd.getpwnam('pi').pw_uid
cadm_home = pwd.getpwnam('pi').pw_dir
cadm_gid = grp.getgrnam('pi').gr_gid

syslog = logging.getLogger('webservice.server')
syslog.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address = '/dev/log')
formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
handler.setFormatter(formatter)
syslog.addHandler(handler)


def delpid():
  try:
    os.remove(lockFileName)
  except:
    syslog.info('someone already deleted '+lockFileName)


def sigterm_handler(signum, frame):
  syslog.info('webservice.server shutdown')
  sys.exit()


def sigint_handler(signum, frame):
  syslog.info('webservice.server shutdown')
  sys.exit()


def initial_program_setup_user():
  global syslog
  syslog.info('webservice.server startup')


def initial_program_setup_root():
  if (cadm_gid==0):
    print ("I am not willing to run in group root")
    os.exit(1)
  if (cadm_uid==0):
    print ("I am not willing to run as root")
    os.exit(1)

  try:
    os.mkdir(lockFileDir)
    os.chown(lockFileDir, cadm_uid, cadm_gid)
  except OSError as err:
    print ("cannot mkdir "+lockFileName+" {0}\n)".format(err))

  signal.signal(signal.SIGTERM, sigterm_handler)
  signal.signal(signal.SIGINT,  sigint_handler)

  groups = [ 997, 999 ] # gpio and spi
  os.setgroups(groups)
  os.setgid(cadm_gid)
  os.setuid(cadm_uid)


def reload():
  syslog.info('webservice.server reload')


class LoggingSimpleXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    def log_message(self, format, *args):
      cur_thread = threading.current_thread()
      syslog.debug("%s",cur_thread.name)
      syslog.info("%s - - [%s] %s\n" %
                     (self.address_string(),
                      self.log_date_time_string(),
                      format%args))

    def do_POST(self):
        clientIP, port = self.client_address
	# Log client IP and Port
        syslog.info('Client IP: %s - Port: %s' % (clientIP, port))
        try:
            # get arguments
            data = self.rfile.read(int(self.headers["content-length"]))
            # Log client request
            if (DEBUG):
              syslog.info('Client request: \n%s\n' % data)
        
            response = self.server._marshaled_dispatch(data, getattr(self, '_dispatch', None))
	    # Log server response
            if (DEBUG):
              syslog.info('Server response: \n%s\n' % response)
        
        except: # This should only happen if the module is buggy
            # internal error, report as HTTP server error
            self.send_response(500)
            self.end_headers()
        else:
            # got a valid XML RPC response
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

            # shut down the connection
            self.wfile.flush()
            self.connection.shutdown(1)


def do_main_program():
  # Restrict to a particular path.
  class RequestHandler(LoggingSimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)
  
  # Create server
  #server = SimpleXMLRPCServer(("localhost", 8000), requestHandler=RequestHandler)
  class AsyncXMLRPCServer(socketserver.ThreadingMixIn,SimpleXMLRPCServer): pass
  server = AsyncXMLRPCServer(('localhost', 8000), requestHandler=RequestHandler)
  addUserLock = threading.Lock()

  pifacedigital = pifacedigitalio.PiFaceDigital()

  # Register an instance; all the methods of the instance are
  # published as XML-RPC methods (in this case, just 'mul').
  class MyFuncs:

    def alive(self):
       """alive() returns process id of server"""
       return  os.getpid()

    def rng(self, length):
       """rng(len) returns len number ob random bytes"""
       rngdev = "/dev/urandom"
       f = open(rngdev, "rb")
       rn = bytearray()
       for n in range(1, length):
         byte = f.read(1)
         rn.extend (byte)
       return  str (rn)

    def setOut(self, port, state):
       """setOut(port, state) set output port to state"""
       try:
         if (int(state) == 1):
           pifacedigital.output_pins[int(port)].turn_on()
         else:
           pifacedigital.output_pins[int(port)].turn_off()
       except OSError as err:
         syslog.error('port: {0}\n'.format(err))
         
       #return "port "+port+" set to "+state
       return "ok"

    def getIn(self):
       """getIn(port) get input port state"""
       return pifacedigital.input_port.value

    def _methodHelp(self, method):
      f = getattr(self, method)
      return inspect.getdoc(f)

  server.register_introspection_functions()
  server.register_instance(MyFuncs())
 
  # Run the server's main loop
  server.serve_forever()


initial_program_setup_root()
initial_program_setup_user()

if (DEBUG):
  do_main_program()
else:

  # see http://www.jejik.com/files/examples/daemon3x.py
  try:
    with open(lockFileName,'r') as pf:
      pid = int(pf.read().strip())
  except IOError:
    pid = None

  if pid:
    message = "pidfile {0} already exist. Daemon already running?\n"
    sys.stderr.write(message.format(lockFileName))
    sys.exit(1)

  try:
    pid = os.fork()
    if pid > 0:
      syslog.info ("first fork daemon")
      # exit first parent
      sys.exit(0)
  except OSError as err:
    sys.stderr.write('fork #1 failed: {0}\n'.format(err))
    sys.exit(1)

  os.chdir("/")
  os.setsid()
  os.umask(0)

  try:
    pid = os.fork()
    if pid > 0:
      # exit from second parent
      syslog.info ("second fork daemon")
      sys.exit(0)
  except OSError as err:
    sys.stderr.write('fork #2 failed: {0}\n'.format(err))
    sys.exit(1)

  # redirect standard file descriptors
  sys.stdout.flush()
  sys.stderr.flush()
  si = open(os.devnull, 'r')
  so = open(os.devnull, 'a+')
  se = open(os.devnull, 'a+')

  os.dup2(si.fileno(), sys.stdin.fileno())
  os.dup2(so.fileno(), sys.stdout.fileno())
  os.dup2(se.fileno(), sys.stderr.fileno())

  atexit.register(delpid)

  pid = str(os.getpid())
  try:
    with open(lockFileName,'w+') as f:
      f.write(pid + '\n')
  except:
    sys.stderr.write('cannot open pid file')
    sys.exit(1)

  do_main_program()

