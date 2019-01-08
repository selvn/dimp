#!/usr/bin/env python
#coding:utf-8
import socket,sys
import json
import math
from lib import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256

HOST = '127.0.0.1'
PORT = 8998
ADDR =(HOST,PORT) 
BUFSIZE = 2048

sock = socket.socket()

moki_seed = 'moki';
moki_pub = '''-----BEGIN PUBLIC KEY-----
MIGJAoGBALQOcgxhhV0XiHELKYdG587Tup261qQ3ahAGPuifZvxHXTq+GgulEyXiovwrVjpz7rKXn+16HgspLHpp5agv0WsSn6k2MnQGk5RFXuilbFr/C1rEX2X7uXlUXDMpsriKFndoB1lz9P3E8FkM5ycG84hejcHB+R5yzDa4KbGeOc0tAgMBAAE=
-----END PUBLIC KEY-----
''';
moki_fingerprint = 'ld68TnzYqzFQMxeJ6N+aZa2jRf9d4zVx4BUiBlmur67ne8YZF08plhCiIhfyYDIwwW7KLaAHvK8gJbp0pPIzLR4bhzu6zRpDLzUQsq6bXgMp+WAiZtFm6IHWNUwUEYcr3iSvTn5L1HunRt7kBglEjv8RKtbNcK0t1Xto375kMlo=';

moki_meta = {
	'version' : 0x01,
	'seed'    : moki_seed,
	'key'     : moki_pub,
	'fingerprint' : moki_fingerprint
};
#get_meta( moki_seed, moki_fingerprint, moki_pub );
moki_address = '4WDfe3zZ4T7opFSi3iDAKiuTnUHjxmXekk';
# moki_ID = get_ID(moki_seed, moki_address, moki_meta);

pw = 'dimdimdimdim____';
AES_key = {
	'algorithm':'AES',
	'keySize':16,
	'data':base64.b64encode(str.encode(pw))
};
# e = encrypt_message(pw, 'ld68TnzYqzFQMxeJ6N fdwfewa,f mwklfjawljfelwafjkle');
# s = decrypt_message(pw,e);

sock.connect(ADDR)
print('have connected with server');
with open('public.pem','r') as f:
	station_pub = f.read();
with open('moki_private_key.pem','r') as f:
	moki_private = f.read();
moki_connected = False;

while True:
	data = input('lockey# ');
	if len(data)>0:
		send_data = data;
		if data == '1':
			say_hello = {
				'sender'   : moki_seed+'@'+moki_address,
				'receiver' : "dim_hk",
				'time'     : math.floor(time.time()),
				'meta'     : moki_meta,
				'content' : {
					'type'    : 0x88, # DIMMessageType_Command
					'sn'      : 1234,
					'command' : "handshake",
					'message' : "Hello world!" 
				}
			};

			data_to_send = handle_data_to_be_sent(say_hello,station_pub,moki_private, '111111' )

			print('send:',data_to_send);
			sock.sendall(json.dumps(data_to_send).encode('utf-8')); #不要用send()
			recv_data = sock.recv(BUFSIZE);
			# step 3: Client 收到 Station 发送的身份验证请求包后，必须回复一个身份确认响应包：
			print('step 3: received:',recv_data.decode('utf-8'));
			recv_data_json = json.loads(recv_data.decode('utf-8'));
			station_pw = bytes.decode(decrypt(moki_private, recv_data_json['key']));
			content = json.loads(decrypt_message(station_pw, recv_data_json['data']));
			station_random_string = content['session'];
			print('station random string is: ', station_random_string);

			confirm_response = {
				'sender'   : moki_seed+'@'+moki_address,
				'receiver' : "dim_hk",
				'time'     : math.floor(time.time()),
				
				'content'  : {
					'type'    : 0x88, # DIMMessageType_Command
					'sn'      : 34356,
					'command' : "handshake",
					'message' : "Hello world!", # It's me!
					'session' : station_random_string # 由 Station 生成的随机字符串
				}
			}

			confirm_response_to_send = handle_data_to_be_sent(confirm_response,station_pub,moki_private, '111111' );
			sock.sendall(json.dumps(confirm_response_to_send).encode('utf-8')); 

			# step 4: 如果 Station 验证后发现 session 信息不匹配，则拒绝服务并断开链接，否则回复身份确认信息包并继续后续通讯：
			last_recv_data = sock.recv(BUFSIZE);
			print('receive:',last_recv_data.decode('utf-8'));
			last_recv_data_json = json.loads(last_recv_data.decode('utf-8'));
			last_station_pw = bytes.decode(decrypt(moki_private, last_recv_data_json['key']));
			last_content = json.loads(decrypt_message(last_station_pw, last_recv_data_json['data']));
			print('last content: ', last_content);
			moki_connected = True;
		elif(data == '3'):
			station_random_string = '88EELWZ92F5A';
			print('station random string is: ', station_random_string);

			confirm_response = {
				'sender'   : moki_seed+'@'+moki_address,
				'receiver' : "dim_hk",
				'time'     : math.floor(time.time()),
				
				'content'  : {
					'type'    : 0x88, # DIMMessageType_Command
					'sn'      : 34356,
					'command' : "handshake",
					'message' : "Hello world!", # It's me!
					'session' : station_random_string # 由 Station 生成的随机字符串
				}
			}

			confirm_response_to_send = handle_data_to_be_sent(confirm_response,station_pub,moki_private, '111111' );
			sock.sendall(json.dumps(confirm_response_to_send).encode('utf-8')); 

			# step 4: 如果 Station 验证后发现 session 信息不匹配，则拒绝服务并断开链接，否则回复身份确认信息包并继续后续通讯：
			last_recv_data = sock.recv(BUFSIZE);
			print('receive:',last_recv_data.decode('utf-8'));
			last_recv_data_json = json.loads(last_recv_data.decode('utf-8'));
			last_station_pw = bytes.decode(decrypt(moki_private, last_recv_data_json['key']));
			last_content = json.loads(decrypt_message(last_station_pw, last_recv_data_json['data']));
			print('last content: ', last_content);
			moki_connected = True;
	else:
		sock.close()
		break
# try:
# except Exception as e:
# 	print(e);
# 	sock.close()
# 	sys.exit()