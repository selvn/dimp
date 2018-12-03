#!/usr/bin/env python
from socketserver import BaseRequestHandler,ThreadingTCPServer
import time
import sys 
import socket
import threading
import datetime
import time

BUF_SIZE = 1024;

class meta:
    version = 1;
	seed = "";
	key = "";
	fingerprint = "";

	def __init__(self, seed, key, fingerprint):
		self.seed = seed;
		self.key = key;
		self.fingerprint = fingerprint;

class Handler(BaseRequestHandler):
	def handle(self):
		address,pid = self.client_address
		print('%s connected!'%address)
		while True:
			data = self.request.recv(BUF_SIZE)
			if len(data)>0:
				print('receive=',data.decode('utf-8'))
				cur_thread = threading.current_thread()
				#response = '{}:{}'.format(cur_thread.ident,data)
				self.request.sendall('response'.encode('utf-8'))
				print('send:','response')
			else:
				print('close')
				break

if __name__ == '__main__':
	HOST = '127.0.0.1'
	PORT = 8998
	ADDR = (HOST,PORT)
	server = ThreadingTCPServer(ADDR,Handler)  #参数为监听地址和已建立连接的处理类
	print('listening')
	server.serve_forever()  #监听，建立好TCP连接后，为该连接创建新的socket和线程，并由处理类中的handle方法处理
	print(server);
