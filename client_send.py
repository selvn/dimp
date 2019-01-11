#!/usr/bin/env python
#coding:utf-8
import socket,sys
import json
import math
import ast
from time import sleep
import threading
from threading import Thread
from lib import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256

BUFF_SIZE = 4096 # 4KiB

sock = socket.socket()
with open('public.pem','r') as f:
	station_pub = f.read();
sv_server_ID = get_ID_from_string('sv_station@4WBVGYQCurdFyhAgp3Jzn28d9JEmYL9Kpp');
moki_ID = get_ID_from_string('moki@4WDfe3zZ4T7opFSi3iDAKiuTnUHjxmXekk');
with open('resources/moki_private_key.pem','r') as f:
	moki_private = f.read();
with open('resources/moki_public_key.pem','r') as f:
	moki_public = f.read();
moki_fingerprint = 'ld68TnzYqzFQMxeJ6N+aZa2jRf9d4zVx4BUiBlmur67ne8YZF08plhCiIhfyYDIwwW7KLaAHvK8gJbp0pPIzLR4bhzu6zRpDLzUQsq6bXgMp+WAiZtFm6IHWNUwUEYcr3iSvTn5L1HunRt7kBglEjv8RKtbNcK0t1Xto375kMlo=';
moki_meta = {
	'version' : 0x01,
	'seed'    : moki_ID['name'],
	'key'     : moki_public,
	'fingerprint' : moki_fingerprint
};
hulk_ID = get_ID_from_string('hulk@4YeVEN3aUnvC1DNUufCq1bs9zoBSJTzVEj');
with open('resources/hulk_private_key.pem','r') as f:
	hulk_private = f.read();
with open('resources/hulk_public_key.pem','r') as f:
	hulk_public = f.read();
hulk_fingerprint = 'jIPGWpWSbR/DQH6ol3t9DSFkYroVHQDvtbJErmFztMUP2DgRrRSNWuoKY5Y26qL38wfXJQXjYiWqNWKQmQe/gK8M8NkU7lRwm+2nh9wSBYV6Q4WXsCboKbnM0+HVn9Vdfp21hMMGrxTX1pBPRbi0567ZjNQC8ffdW2WvQSoec2I=';
hulk_meta = {
	'version' : 0x01,
	'seed'    : hulk_ID['name'],
	'key'     : hulk_public,
	'fingerprint' : hulk_fingerprint
};
users = {
	'moki':{
		'id':moki_ID,
		'public': moki_public,
		'private':moki_private,
		'fingerprint':moki_fingerprint,
		'meta':moki_meta
	},
	'hulk':{
		'id':hulk_ID,
		'public':hulk_public,
		'private':hulk_private,
		'fingerprint':hulk_fingerprint,
		'meta':hulk_meta
	}
};
userd_user = '';
pw = 'dimdimdimdim____';
AES_key = {
	'algorithm':'AES',
	'keySize':16,
	'data':base64.b64encode(str.encode(pw))
};
# e = encrypt_message(pw, 'ld68TnzYqzFQMxeJ6N fdwfewa,f mwklfjawljfelwafjkle');
# s = decrypt_message(pw,e);

moki_connected = False;
hulk_connected = False;

def handler_single_message( message_json ):
	sender_id = get_ID_from_string(message_json['sender']);
	received_data_pw = bytes.decode(decrypt(users[userd_user]['private'], message_json['key']));
	content = json.loads(decrypt_message(received_data_pw, message_json['data']));
	if( 'command' in content and content['command'] == 'handshake'):
		if( content['message'] == 'DIM?' ):
			station_random_string = content['session'];
			# print('station random string is: ', station_random_string);

			confirm_response = {
				'sender'   : users[userd_user]['id']['name']+'@'+users[userd_user]['id']['address'],
				'receiver' : sv_server_ID['name'] + '@' + sv_server_ID['address'],
				'time'     : math.floor(time.time()),
				
				'content'  : {
					'type'    : 0x88, # DIMMessageType_Command
					'sn'      : 34356,
					'command' : "handshake",
					'message' : "Hello world!", # It's me!
					'session' : station_random_string # 由 Station 生成的随机字符串
				}
			}

			confirm_response_to_send = handle_data_to_be_sent(confirm_response,station_pub,users[userd_user]['private'], '111111' );
			sock.sendall(json.dumps(confirm_response_to_send).encode('utf-8'));
		elif( content['message'] == 'DIM!' ):
			print('%s Logged in!' % userd_user)
	elif( content['type'] == 0x01 ):
		print('%s %s : %s' % ( time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(message_json['time'])), sender_id['name'], content['text']))


def receive_message_handler(arg1, stop_event ):
	while True:
		received_data = b''
		while True:
			part = sock.recv(BUFF_SIZE)
			received_data += part
			if len(part) < BUFF_SIZE:
				break
		# print('received:',received_data.decode('utf-8'));
		recevied_array = received_data.decode('utf-8').splitlines()
		for data1 in recevied_array:
			try:
				recv_data_json = ast.literal_eval(data1);
			except ValueError:
				print( 'Phare data failed: ' + data1 );
			except SyntaxError:
				print( 'SyntaxError: ' + data1 );
			else:
				handler_single_message(recv_data_json);

def send_step1( use_user ):
	say_hello = {
		'sender'   : users[use_user]['id']['name']+'@'+users[use_user]['id']['address'],
		'receiver' : sv_server_ID['name'] + '@' + sv_server_ID['address'],
		'time'     : math.floor(time.time()),
		'meta'     : users[use_user]['meta'],
		'content' : {
			'type'    : 0x88, # DIMMessageType_Command
			'sn'      : 1234,
			'command' : "handshake",
			'message' : "Hello world!" 
		}
	};

	data_to_send = handle_data_to_be_sent(say_hello,station_pub,users[use_user]['private'], '111111' )

	print('send:',data_to_send);
	sock.sendall(json.dumps(data_to_send).encode('utf-8')); #不要用send()

def send_message_handler( arg1, stop_event ):
	print(111)

if __name__ == '__main__':
	HOST = '127.0.0.1'
	PORT = 8998
	print('please input server address(defualt:127.0.0.1:8998), enter for default: ')
	data = input('input# ')
	if(len(data)>0)
		tmp_array = data.split(':')
		HOST = tmp_array[0]
		PORT = tmp_array[1]
	ADDR =(HOST,PORT) 
	sock.connect(ADDR)
	print('have connected with server');
	stop_event1 = threading.Event()
	thread1 = Thread(target = receive_message_handler, args=(1, stop_event1))
	thread1.start()

	stop_event2 = threading.Event()
	thread2 = Thread(target = send_message_handler, args=(1, stop_event2))
	# thread2.start()
	while True:
		data = input('lockey# ');
		if len(data)>0:
			if data == '1':
				userd_user = 'moki'
				send_step1(userd_user);
			elif(data == '2'):
				userd_user = 'hulk'
				send_step1(userd_user);
			else:
				# moki send message to hulk
				target_user = 'hulk' if userd_user == 'moki' else 'moki'
				message = {
					'sender'   : users[userd_user]['id']['name']+'@'+users[userd_user]['id']['address'],
					'receiver' : users[target_user]['id']['name']+'@'+users[target_user]['id']['address'],
					'time'     : math.floor(time.time()),
					
					'content'  : {
						'type'    : 0x01, # DIMMessageType_Command
						'sn'      : 34356,
						'text' : data
					}
				}
				message_to_send = handle_data_to_be_sent(message,users[target_user]['public'],users[userd_user]['private'], '111111' );
				sock.sendall(json.dumps(message_to_send).encode('utf-8')); 
		else:
			print('input nothing')
			sock.close()
			# stop_event1.set()
			break

