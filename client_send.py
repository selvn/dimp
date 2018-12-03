#!/usr/bin/env python
#coding:utf-8
import socket,sys
HOST = '127.0.0.1'
PORT = 8998
ADDR =(HOST,PORT)
BUFSIZE = 1024

sock = socket.socket()
try:
	sock.connect(ADDR)
	print('have connected with server')
	
	meta.version     = 0x01;
	meta.seed        = "moky";
	meta.key         = PK;
	meta.fingerprint = sign(meta.seed, SK);

	while True:
		data = input('lockey# ')
		if len(data)>0:
			print('send:',data)
			sock.sendall(data.encode('utf-8')) #不要用send()
			recv_data = sock.recv(BUFSIZE)
			print('receive:',recv_data.decode('utf-8'))
		else:
			sock.close()
			break
except Exception:
	print('error')
	sock.close()
	sys.exit()