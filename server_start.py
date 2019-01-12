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
import logging
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from threading import Thread
from time import sleep
from lib import *

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(message)s')

# create a debug handler
log_debug_handler = logging.FileHandler('logs/debug.log')
log_debug_handler.setLevel(logging.DEBUG)
log_debug_handler.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(log_debug_handler)

# create a debug handler
log_info_handler = logging.FileHandler('logs/info.log')
log_info_handler.setLevel(logging.INFO)
log_info_handler.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(log_info_handler)

logger.debug('Hello baby')

BUF_SIZE = 2048;

class Handler(BaseRequestHandler):
	def handle_handshake_step_1(self, receiver_ID):
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
	def get_message_sent_response(self, receiver_ID):
		response = {
			'sender'   : station_name+'@'+station_address,
			'receiver' : receiver_ID['name'] + '@' + receiver_ID['address'],
			'time'     : math.floor(time.time()),
			'content'  : {
				'type'    : 0x88, # DIMMessageType_Command
				'sn'      : math.floor(time.time()),
				'command' : "message",
				'message' : "Message sent!"
			}
		};
		return response;
			
	def save_user_meta(self, user_ID, meta):
		user_directory = 'users/'+user_ID['address'];
		if not os.path.exists(user_directory):
			os.makedirs(user_directory + '/messages');
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
		verify_result = verify(data_json['data'].encode('utf-8'), sender_signature, user_public );
		if( verify_result == False ):
			print( 'verify failed!');
			return False;
		return True;

	def if_verify(self, pid, sender_ID):
		if( pid in verified_pids ):
			if( verified_pids[pid][0] == sender_ID['address']):
				return True;
		return False;

	def handle(self):
		address,pid = self.client_address;
		logger.info('%s connected! pid: %s' % (address, pid))
		print('%s connected! pid: %s' % (address, pid));
		while True:
			data = self.request.recv(BUF_SIZE)
			if len(data)>0:
				logger.info( ('%s %s : ' +data.decode('utf-8')) % (address, pid) )
				data_json = json.loads(data.decode('utf-8'));
				# 每次发送数据都验证发送方的合法性
				data_verify_result = self.verify( data_json );
				if( data_verify_result == False ):
					break;
				sender_ID = get_ID_from_string(data_json['sender']);
				# 检查接收方
				receiver_ID = get_ID_from_string(data_json['receiver']);
				if( receiver_ID['address'] == station_address ):
					# 如果是发给服务器的消息, 应该是握手
					encrypted_key = data_json['key'];
					pw_byte = decrypt(station_private_key, encrypted_key);
					print(pw_byte)
					print('===')
					print(pw_byte)
					
					content = json.loads(decrypt_message(pw_byte, data_json['data']).decode('utf-8'));
					response = {};
					if( 'command' in content and content['command'] == 'handshake' ):
						if 'session' in content:
							# 有session, step 3
							response = self.handle_handshake_step_3(content, sender_ID);
							if( response == False ):
								# 验证session不通过, 断开重新验证
								break;
							verified_pids[pid]=[sender_ID['address'], self];
							print(verified_pids)
						else:
							# 没有session, 是step 1
							self.save_user_meta(sender_ID, data_json['meta']);
							response = self.handle_handshake_step_1( sender_ID);
							print('step 2');
					user_public = get_user_public( sender_ID );
					response = handle_data_to_be_sent( response, user_public, station_private_key, '111111');
					self.request.sendall(json.dumps(response).encode('utf-8'));
					print('response pid '+str(pid)+': ',response);
				else:
					#发送给其他人的, 丢到其他人的收件箱
					# 先检查有没有登陆, 还有发送方是不是之前登陆方
					if( self.if_verify(pid, sender_ID) == False ):
						logger.debug('not login')
						print('not login')
						break;
					else:
						receiver_ID = get_ID_from_string(data_json['receiver']);
						store_message( receiver_ID['address'], data.decode('utf-8'));
						response = self.get_message_sent_response( sender_ID );
						user_public = get_user_public( sender_ID );
						response = handle_data_to_be_sent( response, user_public, station_private_key, '111111');
						self.request.sendall(json.dumps(response).encode('utf-8'));
						print( 'response %s: %s' % ( sender_ID['name'], response) );
			else:
				#断开连接, 删除登录态
				if( pid in verified_pids ):
					verified_pids.pop(pid);
				print('closed, pid: ', verified_pids);
				break;
verified_pids = {};
def scan_messages(arg):
	while True:
		logger.debug('scanning...')
		for pid, handler_array in verified_pids.items():
			for file_name in os.listdir(root_path + 'users/' + handler_array[0] + '/messages'): 
				file_path = os.path.join(root_path + 'users/' + handler_array[0] + '/messages', file_name) 
				try:
					with open(file_path,'r') as f:
						data = f.read();
						handler_array[1].request.sendall(data.encode('utf-8'));
					logger.debug('scanning address %s %s' % (handler_array[0], file_path))
					os.remove(file_path)
				except:
					print( 'errorrrrrrrrrrrrrr' )
				sleep(0.5)
		sleep(1)

if __name__ == '__main__':
	print(chr(0).encode("utf-8"))
	pw = random_string(16)
	encrypted_message = encrypt_message(pw.encode('utf-8'), b'Hello world!!!!!')
	print(encrypted_message)
	o_message = decrypt_message(pw.encode('utf-8'), encrypted_message)
	print(o_message)
	# 发起一个线程, 扫描信息
	thread = Thread(target = scan_messages, args = (10, ))
	thread.start()
	print ("thread finished...exiting")


	station_name = 'sv_station';
	with open('public.pem','r') as f:
		station_pubic_key = f.read();
	with open('private.pem','r') as f:
		station_private_key = f.read();
	
	station_fingerprint = rsa_sign(station_name.encode('utf-8'), station_private_key, '111111');
	station_address = btc_build_address( station_fingerprint );
	# text = decrypt(station_private_key, encrypted_key);
	# print(text);
	with open('resources/moki_public_key.pem','r') as f:
		moki_pub = f.read();
	HOST = '0.0.0.0'
	PORT = 8998;
	ADDR = (HOST,PORT);
	socketserver.TCPServer.allow_reuse_address = True;
	server = ThreadingTCPServer(ADDR,Handler)  #参数为监听地址和已建立连接的处理类
	print( station_name+'@'+ station_address +' is listening...');
	server.serve_forever()  #监听，建立好TCP连接后，为该连接创建新的socket和线程，并由处理类中的handle方法处理
	print(server);
