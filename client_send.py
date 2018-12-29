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
BUFSIZE = 1024

sock = socket.socket()

moki_seed = 'moki';
moki_pub = '''-----BEGIN PUBLIC KEY-----
MIGJAoGBALQOcgxhhV0XiHELKYdG587Tup261qQ3ahAGPuifZvxHXTq+GgulEyXiovwrVjpz7rKXn+16HgspLHpp5agv0WsSn6k2MnQGk5RFXuilbFr/C1rEX2X7uXlUXDMpsriKFndoB1lz9P3E8FkM5ycG84hejcHB+R5yzDa4KbGeOc0tAgMBAAE=
-----END PUBLIC KEY-----
''';
moki_fingerprint = 'ld68TnzYqzFQMxeJ6N+aZa2jRf9d4zVx4BUiBlmur67ne8YZF08plhCiIhfyYDIwwW7KLaAHvK8gJbp0pPIzLR4bhzu6zRpDLzUQsq6bXgMp+WAiZtFm6IHWNUwUEYcr3iSvTn5L1HunRt7kBglEjv8RKtbNcK0t1Xto375kMlo=';
moki_private = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC0DnIMYYVdF4hxCymHRufO07qdutakN2oQBj7on2b8R106vhoLpRMl4qL8K1Y6c+6yl5/teh4LKSx6aeWoL9FrEp+pNjJ0BpOURV7opWxa/wtaxF9l+7l5VFwzKbK4ihZ3aAdZc/T9xPBZDOcnBvOIXo3Bwfkecsw2uCmxnjnNLQIDAQABAoGADi5wFaENsbgTh0HHjs/LHKto8JjhZHQ33pS7WjOJ1zdgtKp53y5sfGimCSH5q+drJrZSApCCcsMWrXqPO8iuX/QPak72yzTuq9MEn4tusO/5w8/g/csq+RUhlLHLdOrPfVciMBXgouT8BB6UMa0e/g8K/7JBV8v1v59ZUccSSwkCQQD67yI6uSlgy1/NWqMENpGc9tDDoZPR2zjfrXquJaUcih2dDzEbhbzHxjoScGaVcTOx/Aiu00dAutoN+Jpovpq1AkEAt7EBRCarVdo4YKKNnW3cZQ7u0taPgvc/eJrXaWES9+MpC/NZLnQNF/NZlU9/H2607/d+Xaac6wtxkIQ7O61bmQJBAOUTMThSmIeYoZiiSXcrKbsVRneRJZTKgB0SDZC1JQnsvCQJHld1u2TUfWcf3UZH1V2CK5sNnVpmOXHPpYZBmpECQBp1hJkseMGFDVneEEf86yIjZIM6JLHYq2vT4fNr6C+MqPzvsIjgboJkqyK2sLj2WVm3bJxQw4mXvGP0qBOQhQECQQCOepIyFl/a/KmjVZ5dvmU2lcHXkqrvjcAbpyO1Dw6p2OFCBTTQf3QRmCoys5/dyBGLDhRzV5Obtg6Fll/caLXs
-----END RSA PRIVATE KEY-----''';

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
print('have connected with server')

while True:
	data = input('lockey# ')
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

			station_pub = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrNbY6/SkGW/NhF1BZIZIQawqP
X19ucCMQP8jq5C5PAk6593Nm3AIm9OLKTAaW8THy/8Zgnel0vFQAfDpuxHg9tp5x
3kk1VZwr9hl173NvMT0fHBHatLFfnl5D6s+5yRfWJiUA4L35E2Z774Rg/vj3GlCb
/mqPsQ+ZMdMx19FdhwIDAQAB
-----END PUBLIC KEY-----''';

			with open('public.pem','r') as f:
				station_pub = f.read();

			# key = encrypt( station_pub, pw );
			# print(key);
			# say_hello['key'] = key;

			# content_string = json.dumps(content);
			# data = encrypt_message(pw, content_string);
			# say_hello['data'] = data;

			
			# signature = rsa_sign(data, moki_private, '111111' );
			# print( signature);
			# say_hello['signature'] = signature;
			# data = say_hello;

			data_to_send = handle_data_to_be_sent(say_hello,station_pub,moki_private, '111111' )

		print('send:',data_to_send);
		sock.sendall(json.dumps(data_to_send).encode('utf-8')); #不要用send()
		recv_data = sock.recv(BUFSIZE);
		print('receive:',recv_data.decode('utf-8'));
	else:
		sock.close()
		break
# try:
# except Exception as e:
# 	print(e);
# 	sock.close()
# 	sys.exit()