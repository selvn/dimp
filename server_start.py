#!/usr/bin/env python
#coding:utf-8
import socketserver
from socketserver import BaseRequestHandler,ThreadingTCPServer
import time
import json
import sys 
import socket
import threading
import datetime
import hashlib
import base58
import base64
import math
import random
import string
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from lib import *

BUF_SIZE = 2048;

class Handler(BaseRequestHandler):
	def handle_handshake_step_1(self, content, receiver_ID):
		print('step1');
		
		response = {
			'sender'   : station_name+'@'+station_address,
			'receiver' : receiver_ID['name'] + '@' + receiver_ID['address'],
			'time'     : math.floor(time.time()),
			'content'  : {
				'type'    : 0x88, # DIMMessageType_Command
				'sn'      : 1579,
				'command' : "handshake",
				'message' : "DIM?",
				'session' : ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
			}
		};
		return response;

	def handle(self):
		address,pid = self.client_address
		print('%s connected!'%address)
		while True:
			data = self.request.recv(BUF_SIZE)
			if len(data)>0:
				print('receive=',data.decode('utf-8'));
				# cur_thread = threading.current_thread();
				#response = '{}:{}'.format(cur_thread.ident,data)
				data_json = json.loads(data.decode('utf-8'));
				print(type(data));
				print( type( data_json));
				print( type(data_json['sender']));
				sender_ID = get_ID_from_string(data_json['sender']);
				print(type(sender_ID));
				print(sender_ID);
				sender_meta = data_json['meta'];
				print(type(sender_meta));
				print(sender_meta);
				# 判断ID和meta是不是相符
				if( is_match(sender_ID, sender_meta) == False ):
					self.request.sendall('ID and meta does not match! Reject!'.encode('utf-8'));
					break;
				# 获取签名然后验签
				sender_signature = data_json['signature'];
				# 用户pk会在第一次握手传过来
				user_public = data_json['meta']['key'];
				verify_result = verify(data_json['data'], sender_signature, user_public );
				print( verify_result);
				if( verify_result == False ):
					print( 'verify failed!');
					break;
				encrypted_key = data_json['key'];
				# print(data_json['key']);
				pw = bytes.decode(decrypt(station_private_key, encrypted_key));
				print(pw);
				content = json.loads(decrypt_message(pw, data_json['data']));
				print(content);
				response = {};
				if( content['command'] == 'handshake' ):
					if 'message' in content:
						response = self.handle_handshake_step_1(content, sender_ID);
					else:
						print('step 2');
				
				print(user_public);
				response = handle_data_to_be_sent( response, user_public, station_private_key, '111111');
				self.request.sendall(json.dumps(response).encode('utf-8'));
				print('sent: ',response);
			else:
				print('closed');
				break

if __name__ == '__main__':
	# encrypted_key = 'b8I+qIsbDKZfayLb3uOkLbiRpodFjHrcyS4p7HBodvu/9Vg+EZiPTzxYKWhDzDCtdeztwmu4C2q5p2YoLEVB+4Fsf4UCOwrRl9xGk1w2q6zojy04vBTd7JRcgTT45FCZVvqfu6oXE7X/NeazsoOrtDb0qJ8iJDNxUlRlPEc9mmk=';
	station_name = 'sv_station';
	with open('public.pem','r') as f:
		station_pubic_key = f.read();
	station_private_key = '''-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,6DFF59F2998C6705

CjP9dxPnTFjoH8rCA2q1MWWAu9wP2K4FE7l6sQyD26GvL314V6nSMWNLaLWLXDEd
AvEk8czhSKZI1NwIPu+v49pP3MdLcqRmLd4epink9Ttz6AWN7W4qeGEgQZLk7s7C
0HbMbYcXZt1WMcf2HuDOYlCef1IF8cIswQk/4+nkW/OaRSGCuZgUdoIpIGq92h7n
qC/0sYQ81jbzwcW6tUaRVapnIveNhiICCwGydC/qsBNPy2/F3uEnqSRSRuq0qHwv
7oUs4D+9No7vgK2PX9GKrKe8r+bo9k1KsCoCCPtN+XfzUNI/E9j9qzIWdjhU52P5
e9jQPpjFi+ATO+R57VXDPiuROLIcRJPFWjKEvjpCMrW3YGhOCD9g5Z/A9Ty8517b
FczmDUmGevVH9YHy4uC+6pjjO6CkctZARiyfa5lS0NqHER2QC2MnzfzuOptgkb9G
8LQ/9xedJ9WUEV2Yx3ly8OkL6cwSPgdoGjVYcXk49RGD/YMByHrXG5X2yvCsVI9X
TtGtDpUuiYGATaZXDFSaRxX/W75LBtviWxGIQiN0EhbmY8C+4nm65+IU6HYlCCLb
+mWnnjzdJnTNSHhcBq4F5qE4UNRX2aldQzI/STipfI4OBVzdFiZRyPmMKnKEfoQ+
Jdb3KyP7mlBaCTfGyZMtpjp4Ls/vWXET7wZE25Q3JNMJ+6Wt30AaBi14J6WSn757
ZXau5EC60WHPH0s2JI4J+YrCfta/n3Fc4lUP7SS3T/K0zanT7ubgs112DpTC7t+n
lXV6eAEYrav8zN5T+a8DtfFIlRDTVsu70qU3Vd1fPRf0DNzswgGkrw==
-----END RSA PRIVATE KEY-----
''';
	station_fingerprint = rsa_sign(station_name, station_private_key, '111111');
	station_address = btc_build_address( station_fingerprint );
	# text = decrypt(station_private_key, encrypted_key);
	# print(text);
	moki_pub = '''-----BEGIN PUBLIC KEY-----
MIGJAoGBALQOcgxhhV0XiHELKYdG587Tup261qQ3ahAGPuifZvxHXTq+GgulEyXiovwrVjpz7rKXn+16HgspLHpp5agv0WsSn6k2MnQGk5RFXuilbFr/C1rEX2X7uXlUXDMpsriKFndoB1lz9P3E8FkM5ycG84hejcHB+R5yzDa4KbGeOc0tAgMBAAE=
-----END PUBLIC KEY-----
''';
	HOST = '127.0.0.1'
	PORT = 8998;
	ADDR = (HOST,PORT);
	socketserver.TCPServer.allow_reuse_address = True;
	server = ThreadingTCPServer(ADDR,Handler)  #参数为监听地址和已建立连接的处理类
	print( station_name+'@'+ station_address +' is listening...');
	server.serve_forever()  #监听，建立好TCP连接后，为该连接创建新的socket和线程，并由处理类中的handle方法处理
	print(server);
