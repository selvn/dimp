#!/usr/bin/env python
#coding:utf-8

import sys 
import datetime
import time
import string
import random
import hashlib
import base58
import base64
import json
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from Crypto import Random

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256

class meta:
	version = b'\x01';
	def __init__(self, seed, fingerprint, key_data, key_algorithm = "RSA"):
		self.seed = seed;
		self.key_data = key_data;
		self.fingerprint = fingerprint;
		self.generate_address();
		
	def generate_address( self ):
		self.address = btc_build_address(self.fingerprint);

class ID:
	def __init__(self, name, address, meta):
		self.meta = meta;
		self.name = self.meta.seed;
		self.address = address;
		self.pub_key = meta.key_data;

	def rsa_sign(self):
		private_key_file = open('hulk_priv_key.pem', 'r')
		privateKeyString = private_key_file.read();
		
		pri_key = RSA.importKey(privateKeyString);
		# rsa.sign(self.seed, pri_key);
		signer = PKCS1_v1_5.new(pri_key)
		hash_obj = SHA256.new(self.seed.encode('utf-8'));
		print(signer.sign(hash_obj));

		signature = signer.sign(hash_obj)
		private_key_file.close();
		print(base64.b64encode(signature));
		return signature;

def get_ID_from_string( ID_string ):
	ID_dict = ID_string.split('@');
	return {
		'name':ID_dict[0],
		'address':ID_dict[1]
	}

# RSA 加密
def encrypt(public_key, data ):
	pub_key = RSA.importKey(public_key);
	cipher = Cipher_PKCS1_v1_5.new(pub_key);
	cipher_text = cipher.encrypt(data.encode('utf-8'));
	emsg = base64.b64encode(cipher_text)
	return bytes.decode(emsg);

def decrypt( private_key, data ):
	key = RSA.importKey(private_key, '111111');
	cipher = Cipher_PKCS1_v1_5.new(key);
	text = cipher.decrypt(base64.b64decode(data),'whatever');
	return text;

# RSA 签名, 生成fingerprint
def rsa_sign( data, private_key, key_passphrase = '' ):
	if(key_passphrase == ''):
		print('empty key____');
		pri_key = RSA.importKey(private_key);
	else:
		pri_key = RSA.importKey(private_key, key_passphrase);
	signer = PKCS1_v1_5.new(pri_key)
	hash_obj = SHA256.new(data.encode('utf-8'));
	signature = signer.sign(hash_obj)
	return (base64.b64encode(signature)).decode();

#RSA 验签
def verify(data, sign, pub_key):
	# """校验RSA 数字签名"""
	hash_value = SHA256.new(data.encode('utf-8'));
	verifier = PKCS1_v1_5.new(RSA.importKey(pub_key));
	return verifier.verify(hash_value, base64.b64decode(sign));

def btc_build_address( fingerprint, network = b'\x08' ):
	fingerprintBytes = base64.b64decode(fingerprint);
	sha256hash = hashlib.sha256(fingerprintBytes).digest();
	# print( b'sha256hash: ' + sha256hash);
	hashlibObj = hashlib.new('ripemd160');
	hashlibObj.update(sha256hash);
	hash = hashlibObj.digest();
	tmpString = network + hash;
	checkCode = hashlib.sha256( hashlib.sha256( tmpString ).digest() ).digest();
	# print(b'check code: ' + checkCode);
	addressString = network + hash + checkCode[:4];
	address = base58.b58encode(( addressString ));
	return bytes.decode(address);

# 判断ID和Meta是不是相符
def is_match(ID, meta):
	# 1. 首先检查 Meta 信息中的 seed、key、fingerprint 与 ID.name 是否对应
	if( meta['seed'] != ID['name'] ):
		return False;
	if( verify(meta['seed'], meta['fingerprint'], meta['key']) == False):
		return False;

	# 2. 再由 Meta 算法生成其对应的地址，检查是否与 ID.address 相同
	address = btc_build_address( meta['fingerprint'], b'\x08' );
	if( address != ID['address'] ):
		return False;

	# 3. 以上全部通过，则表示匹配成功，可以接受 meta 中的 key 作为该账号的公钥
	ID['publicKey'] = meta['key'];
	return True;
	

def get_meta( seed, fingerprint, pub ):
	if( verify( seed, fingerprint, pub ) == False):
		return False;
	print( seed + ' verify success!');
	return meta(seed, fingerprint, pub);

def get_ID( name, address, meta1 ):
	if( name != meta1.seed ):
			return;
	print('name passed!');
	
	print(address);
	print(meta1.address);
	if( address != meta1.address ):
		return;
	print('Address passed!');
	return ID(name, address, meta1);

def encrypt_message(pw, json_message ):
	# pw = base64.b64decode(key['data']);
	cryptor = AES.new(pw.encode("utf-8"), AES.MODE_CBC, b'0000000000000000');
	pad_string = json_message + (16 - len(json_message) % 16) * chr(0) 
	ciphertext = cryptor.encrypt(pad_string.encode("utf-8"));
	# 这里统一把加密后的字符串转化为16进制字符串
	# 在下节介绍base64时解释原因
	return bytes.decode(b2a_hex(ciphertext));

def decrypt_message(pw, encrypted_message ):
	ciphertext = a2b_hex(encrypted_message);
	cryptor = AES.new(pw.encode("utf-8"), AES.MODE_CBC, b'0000000000000000');
	plaintext = cryptor.decrypt(ciphertext)
	# 解密后，去掉补足的空格用strip() 去掉
	return bytes.decode(plaintext).rstrip(chr(0));

def random_string( length ):
	return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range( length ));

def handle_data_to_be_sent( data_json, receiver_public_key, sender_private_key, sender_private_key_passphrase ):
	pw = random_string(16);
	content_string = json.dumps( data_json.pop( 'content', None ) );
	encrypted_data = encrypt_message(pw, content_string);
	data_json['data'] = encrypted_data;
	key = encrypt( receiver_public_key, pw );
	data_json['key'] = key;

	signature = rsa_sign(encrypted_data, sender_private_key, sender_private_key_passphrase );
	data_json['signature'] = signature;

	return data_json;

def get_user_public( user_ID ):
	f = open('users/'+user_ID['address']+'/public.key');
	public_string = f.read();
	f.close();
	return public_string;