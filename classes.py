#!/usr/bin/env python
#coding:utf-8
from socketserver import BaseRequestHandler,ThreadingTCPServer
import time
import sys 
import socket
import threading
import datetime
import hashlib
import base58
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from lib import *

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
