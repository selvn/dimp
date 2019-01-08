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
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from lib import *

BUF_SIZE = 2048;

class Handler(BaseRequestHandler):
	def handle_handshake_step_1(self, content, receiver_ID):
		print('step1');
		random_string = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12));
		with open('users/'+receiver_ID['address']+"/verify","w") as f:
			f.write( random_string );

		response = {
			'sender'   : station_name+'@'+station_address,
			'receiver' : receiver_ID['name'] + '@' + receiver_ID['address'],
			'time'     : math.floor(time.time()),
			'content'  : {
				'type'    : 0x88, # DIMMessageType_Command
				'sn'      : 1579,
				'command' : "handshake",
				'message' : "DIM?",
				'session' : random_string
			}
		};
		return response;
	def handle_handshake_step_3(self, content, receiver_ID):
		print('step 4');
		with open('users/'+receiver_ID['address']+"/verify",'r') as f:
			stored_session = f.read();
		
		if( stored_session != content['session'] ):
			return False;
		# session验证通过
		response = {
			'sender'   : station_name+'@'+station_address,
			'receiver' : receiver_ID['name'] + '@' + receiver_ID['address'],
			'time'     : math.floor(time.time()),
			'content'  : {
				'type'    : 0x88, # DIMMessageType_Command
				'sn'      : 1579,
				'command' : "handshake",
				'message' : "DIM!"
			}
		};
		return response;
			
	def save_user_meta(self, user_ID, meta):
		user_directory = 'users/'+user_ID['address'];
		if not os.path.exists(user_directory):
			os.makedirs(user_directory);
		with open(user_directory+"/public.key","w") as f:
			f.write( meta['key'] );
		with open(user_directory+"/fingerprint","w") as f:
			f.write( meta['fingerprint'] );
		return True;

	def verify(self, data_json ):
		sender_ID = get_ID_from_string(data_json['sender']);
		print(sender_ID);
		if 'meta' in data_json:
			sender_meta = data_json['meta'];
			print(type(sender_meta));
			print(sender_meta);
			# 判断ID和meta是不是相符
			if( is_match(sender_ID, sender_meta) == False ):
				self.request.sendall('ID and meta does not match! Reject!'.encode('utf-8'));
				return False;
		# 获取签名然后验签
		sender_signature = data_json['signature'];
		# 用户pk会在第一次握手传过来
		if( 'meta' in data_json ):
			user_public = data_json['meta']['key'];
		else:
			user_public = get_user_public( sender_ID );
		verify_result = verify(data_json['data'], sender_signature, user_public );
		print( verify_result);
		if( verify_result == False ):
			print( 'verify failed!');
			return False;
		return True;

	def handle(self):
		address,pid = self.client_address;
		print('%s connected!' % address);
		while True:
			print('pid: ', pid);
			data = self.request.recv(BUF_SIZE)
			if len(data)>0:
				data_json = json.loads(data.decode('utf-8'));
				data_verify_result = self.verify( data_json );
				if( data_verify_result == False ):
					break;
				sender_ID = get_ID_from_string(data_json['sender']);
				encrypted_key = data_json['key'];
				# print(data_json['key']);
				pw = bytes.decode(decrypt(station_private_key, encrypted_key));
				content = json.loads(decrypt_message(pw, data_json['data']));
				response = {};
				if( content['command'] == 'handshake' ):
					if 'session' in content:
						# 有session, step 3
						response = self.handle_handshake_step_3(content, sender_ID);
						if( response == False ):
							# 验证session不通过, 断开重新验证
							break;
						verified_pids.append(pid);
					else:
						# 没有session, 是step 1
						self.save_user_meta(sender_ID, data_json['meta']);
						response = self.handle_handshake_step_1(content, sender_ID);
						print('step 2');
				
				user_public = get_user_public( sender_ID );
				print(user_public);
				response = handle_data_to_be_sent( response, user_public, station_private_key, '111111');
				self.request.sendall(json.dumps(response).encode('utf-8'));
				print('sent: ',response);
			else:
				if( pid in verified_pids ):
					verified_pids.remove(pid);
				print('closed, pid: ', verified_pids);
				break;

if __name__ == '__main__':
	# encrypted_key = 'b8I+qIsbDKZfayLb3uOkLbiRpodFjHrcyS4p7HBodvu/9Vg+EZiPTzxYKWhDzDCtdeztwmu4C2q5p2YoLEVB+4Fsf4UCOwrRl9xGk1w2q6zojy04vBTd7JRcgTT45FCZVvqfu6oXE7X/NeazsoOrtDb0qJ8iJDNxUlRlPEc9mmk=';
	station_name = 'sv_station';
	with open('public.pem','r') as f:
		station_pubic_key = f.read();
	with open('private.pem','r') as f:
		station_private_key = f.read();
	
	station_fingerprint = rsa_sign(station_name, station_private_key, '111111');
	station_address = btc_build_address( station_fingerprint );
	# text = decrypt(station_private_key, encrypted_key);
	# print(text);
	with open('moki_public_key.pem','r') as f:
		moki_pub = f.read();
	verified_pids = [];
	HOST = '127.0.0.1'
	PORT = 8998;
	ADDR = (HOST,PORT);
	socketserver.TCPServer.allow_reuse_address = True;
	server = ThreadingTCPServer(ADDR,Handler)  #参数为监听地址和已建立连接的处理类
	print( station_name+'@'+ station_address +' is listening...');
	server.serve_forever()  #监听，建立好TCP连接后，为该连接创建新的socket和线程，并由处理类中的handle方法处理
	print(server);
