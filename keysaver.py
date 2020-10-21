'''
file syntax:
	- version (2 byte), b'\x00\x01'
	- encryption method (2 bytes):
	  b'\x00\x01':
	  - argon2 to expand pw to 32 byte key with 32 byte salt
	  - AES GCM global encryption with 12 byte nonce
	  - AES CBC for passwords: 16 byte iv, token as key, no MAC
	  - encrypted data:
	  	- 32 byte salt to derive a token = sha256(salt + pw)
	  	- dictionary stored as msgpack
		- MAC of AES GCM with aad over version, method and argon2 salt

pw_dic['name'] = {'info': {"description": "Mail Telekom Main", "username": "username"},
                       'update_ts': 1234567890,
                       'enc_data': b'salt and encrypted password'}
'''
import argon2
import datetime
import hashlib
import msgpack
import os
import pyperclip
import time

from cryptography.hazmat.backends import default_backend as ht_backend
from cryptography.hazmat.primitives.ciphers import (
		Cipher as HtCipher, algorithms as ht_algorithms, modes as ht_modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as HtAesGcm
from cryptography.exceptions import InvalidTag

from getpass import getpass
from random import SystemRandom as _SystemRandom
from tabulate import tabulate

from ntlib.fctthread import ThreadLoop

__version__ = '0.3.4'
__author__ = 'NTI (lugino-emeritus) <*@*.de>'

FILENAME = "pwdic"
PW_DEFAULT_LEN = 12
MASTER_TOKEN_TIME = 300

_VERSION = b'\x00\x01'
_ENC_METHOD = b'\x00\x01'

#-------------------------------------------------------

def utc_ts():
	return datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
def _utc_msts48():
	return int(utc_ts() * 1000) & (2**48-1)

sys_randint = _SystemRandom().randint  # returns n with a <= n <= b

def pw_lifetime():
	return 86400 * sys_randint(400, 600)

_salt_count = int.from_bytes(os.urandom(4), 'little')
def gen_salt(n):
	global _salt_count
	if n <= 10:
		return os.urandom(n)
	_salt_count = _salt_count+1 if _salt_count < 2**32-1 else 0
	return b''.join((_utc_msts48().to_bytes(6, 'little'), _salt_count.to_bytes(4, 'little'), os.urandom(n-10)))

#-------------------------------------------------------

def _get_number(i):
	assert 0 <= i <= 9
	return chr(48 + i)
def _get_uppercase(i):
	assert 0 <= i <= 25
	return chr(65 + i)
def _get_lowercase(i):
	assert 0 <= i <= 25
	return chr(97 + i)
def _get_symbol(i):
	assert 0 <= i <= 27
	# do not use all possible symbols: ^, ', ", `
	return r'!#$%&()*+,-./:;<=>?@[\]_{|}~'[i]

def _get_char(i): # 0 <= i <= 89 = 26 + 26 + 10 + 28 - 1
	if i < 26:
		return _get_lowercase(i)
	elif i < 52:
		return _get_uppercase(i-26)
	elif i < 62:
		return _get_number(i-52)
	elif i < 90:
		return _get_symbol(i-62)
	raise ValueError('_get_char int too high (valid range: 0 <= i <= 89)')

def gen_rand_pw(n=PW_DEFAULT_LEN):
	if n < 6:
		return ''.join(_get_char(sys_randint(0, 89)) for _ in range(n))

	pwl = [_get_lowercase(sys_randint(0, 25)),
			_get_uppercase(sys_randint(0, 25)),
			_get_number(sys_randint(0, 9)),
			_get_symbol(sys_randint(0, 27))]
	pwl.extend(_get_char(sys_randint(0, 89)) for _ in range(n-4))

	for i in range(n-1):
		j = sys_randint(i, n-1)
		(pwl[i], pwl[j]) = (pwl[j], pwl[i])
	return ''.join(pwl)

#-------------------------------------------------------

def _yes_no_question(s):
	yes = {'yes', 'y', 'j', 'ja'}
	no = {'no', 'n', 'nein'}
	while True:
		choice = input(s).lower()
		if choice in yes:
			return True
		elif choice in no:
			return False
		else:
			print("respond with 'yes' or 'no'")

def _read_new_pw():
	pw = getpass('Enter new password: ')
	while getpass('Repeat password: ') != pw:
		pw = getpass('Passwords are not equal, try again: ')
	return pw.encode()

def _read_rand_pw():
	data = input('To generate random password enter length > 0, 1 means default length ({:d}): '.format(PW_DEFAULT_LEN))
	if data:
		try:
			n = int(data)
			if n:
				if n == 1: n = PW_DEFAULT_LEN
				pw = gen_rand_pw(n)
				if _yes_no_question('New password created, copy to clipboard? '):
					pyperclip.copy(pw)
				return pw.encode()
		except ValueError:
			pass
	return _read_new_pw()

#-------------------------------------------------------

class crypto:
	# static namespace class for cryptography methods
	def aes_cbc_encrypt(key, data):
		iv = gen_salt(16)
		data += b'\x80' + b'\x00' * ((15 - len(data)) % 16)
		encryptor = HtCipher(ht_algorithms.AES(key), ht_modes.CBC(iv), ht_backend()).encryptor()
		return iv + encryptor.update(data) + encryptor.finalize()

	def aes_cbc_decrypt(key, data):
		iv, data = data[:16], data[16:]
		decryptor = HtCipher(ht_algorithms.AES(key), ht_modes.CBC(iv), ht_backend()).decryptor()
		data = decryptor.update(data) + decryptor.finalize()
		return data.rpartition(b'\x80')[0]

	def aes_gcm_encrypt(key, data, aad=b''):
		iv = gen_salt(12)
		return iv + HtAesGcm(key).encrypt(iv, data, aad)

	def aes_gcm_decrypt(key, data, aad=b''):
		iv, data = data[:12], data[12:]
		return HtAesGcm(key).decrypt(iv, data, aad)

	def argon2_param1_hash(key, salt):
		return argon2.low_level.hash_secret_raw(
			type=argon2.Type.ID, secret=key, salt=salt, hash_len=32,
			time_cost=4, parallelism=4, memory_cost=524288)

#-------------------------------------------------------

class DicSaver:
	def __init__(self, filename=FILENAME):
		self.filename = filename
		self._method = None
		self._enc_salt = None
		self._enc_key = None
		self._token_data = None
		self._token = None


	def _refresh_pw(self, pw):
		if self._method == b'\x00\x00':
			self._enc_salt = b''
			self._enc_key = b''
		elif self._method == b'\x00\x01':
			self._enc_salt = gen_salt(32)
			self._enc_key = crypto.argon2_param1_hash(pw, self._enc_salt)
		else:
			raise KeyError('method {!s} unknown'.format(self._method))

	def _check_pw(self, pw):
		if self._method == b'\x00\x00':
			return True
		elif self._method == b'\x00\x01':
			return crypto.argon2_param1_hash(pw, self._enc_salt) == self._enc_key
		else:
			raise KeyError('method {!s} unknown'.format(self._method))

	def _set_token(self, pw):
		if self._method == b'\x00\x00':
			self._token = b''
		elif self._method == b'\x00\x01':
			self._token = hashlib.sha256(self._token_data + pw).digest()
		else:
			raise KeyError('method {!s} unknown'.format(self._method))


	def read(self):
		with open(self.filename, 'rb') as f:
			data = f.read()
		version, self._method, data = data[:2], data[2:4], data[4:]
		if version != _VERSION:
			raise Exception('version not supported')
		salt_len = {b'\x00\x00': 0, b'\x00\x01': 32}[self._method]
		salt, data = data[:salt_len], data[salt_len:]
		aad = _VERSION + self._method + salt

		pw = getpass('Enter master password: ').encode()
		while True:
			try:
				if self._method == b'\x00\x00':
					self._token_data = b''
				elif self._method == b'\x00\x01':
					key = crypto.argon2_param1_hash(pw, salt)
					data = crypto.aes_gcm_decrypt(key, data, aad)
					self._token_data, data = data[:32], data[32:]
				else:
					raise KeyError('method {!s} unknown'.format(self._method))
				break
			except InvalidTag:
				pw = getpass('Wrong password, try again: ').encode()

		self._refresh_pw(pw)
		self._set_token(pw)
		return msgpack.unpackb(data, raw=False)

	def save(self, dic):
		data = msgpack.packb(dic, use_bin_type=True)
		aad = _VERSION + self._method + self._enc_salt

		if self._method == b'\x00\x00':
			pass
		elif self._method == b'\x00\x01':
			data = self._token_data + data
			data = crypto.aes_gcm_encrypt(self._enc_key, data, aad)
		else:
			raise KeyError('method {!s} unknown'.format(self._method))
		with open(self.filename, 'wb') as f:
			f.write(aad + data)


	@property
	def method(self):
		return self._method or b'\x00\x00'

	def change_pw(self, *, method=None):
		if self._enc_key:
			pw = getpass('Enter current master password: ').encode()
			while not self._check_pw(pw):
				pw = getpass('Wrong password, try again: ').encode()
			self._set_token(pw)

		old_token = self._token
		if method:
			self._method = method
		elif not self._method:
			self._method = _ENC_METHOD
		pw = _read_new_pw()

		if self._method == b'\x00\x00':
			self._token_data = b''
		elif self._method == b'\x00\x01':
			self._token_data = gen_salt(32)
		else:
			raise KeyError('method {!s} unknown'.format(self._method))

		self._refresh_pw(pw)
		self._set_token(pw)
		return self._token, old_token

	def get_token(self):
		if self._token is None:
			pw = getpass('Enter master password: ').encode()
			while not self._check_pw(pw):
				pw = getpass('Wrong password, try again: ').encode()
			self._set_token(pw)
		return self._token


class TokenDicSaver(DicSaver):
	def __init__(self, filename=FILENAME):
		super().__init__(filename)
		self._alive_ts = 0
		self._loop_ctl = ThreadLoop(self._loop)

	def _loop(self, cont_task, req_stop):
		while cont_task():
			dt = self._alive_ts - time.time()
			if dt > 30:
				time.sleep(30)
			elif dt > 0:
				time.sleep(dt)
			else:
				req_stop()
		self._token = None

	def _set_token(self, pw):
		super()._set_token(pw)
		self._alive_ts = time.time() + MASTER_TOKEN_TIME
		self._loop_ctl.start()

	def get_token(self):
		if self._loop_ctl.is_alive():
			ts = time.time() + MASTER_TOKEN_TIME
			if ts > self._alive_ts:
				self._alive_ts = ts
		elif self._token is not None:
			self._token = None
			print('\nTOKEN SECURITY ISSUE!!!\n')
		return super().get_token()


def _encrypt_data(token, data, *, method):
	if method == b'\x00\x00':
		return data
	elif method == b'\x00\x01':
		return crypto.aes_cbc_encrypt(token, data)
	else:
		raise KeyError('method {!s} unknown'.format(method))

def _decrypt_data(token, data, *, method):
	if method == b'\x00\x00':
		return data
	elif method == b'\x00\x01':
		return crypto.aes_cbc_decrypt(token, data)
	else:
		raise KeyError('method {!s} unknown'.format(method))

#-------------------------------------------------------

def _alt_file(filename):
	return filename if os.path.exists(filename) else os.path.join(os.path.dirname(__file__), filename)

dic_saver = TokenDicSaver(_alt_file(FILENAME))
pw_dic = None

def read_dic():
	global pw_dic
	pw_dic = dic_saver.read()
def save_dic():
	global pw_dic
	dic_saver.save(pw_dic)

def get_token():
	return dic_saver.get_token()

def change_mpw(method=_ENC_METHOD):
	old_method = dic_saver.method
	token, old_token = dic_saver.change_pw(method=method)
	method = dic_saver.method
	for name in pw_dic:
		pw = _decrypt_data(old_token, pw_dic[name]['enc_data'], method=old_method)
		pw_dic[name]['enc_data'] = _encrypt_data(token, pw, method=method)
	save_dic()

#-------------------------------------------------------

def set_pw(name, pw):
	#pw must be a byte-like object
	pw_dic[name]['enc_data'] = _encrypt_data(dic_saver.get_token(), pw, method=dic_saver.method)
	pw_dic[name]['update_ts'] = int(utc_ts()) + pw_lifetime()
	save_dic()
def get_pw(name):
	#return pw as string
	return _decrypt_data(dic_saver.get_token(), pw_dic[name]['enc_data'], method=dic_saver.method).decode()

def show_pw(name):
	print('username: {!s}, password: {!s}'.format(pw_dic[name]['info']['username'], get_pw(name)))
def copy_pw(name):
	pyperclip.copy(get_pw(name))
	print('username: {!s}, password copied'.format(pw_dic[name]['info']['username']))

def change_pw(name):
	if _yes_no_question('Show current password? '):
		show_pw(name)
	pw = _read_rand_pw()
	set_pw(name, pw)


def add_pw_line(name):
	if name in pw_dic and not _yes_no_question('Name already in pw_dic, overwrite? '):
		return
	pw_info = {}
	pw_info['username'] = input('Username: ')
	pw_info['description'] = input('Description: ')
	pw = _read_rand_pw()
	while _yes_no_question('Do you want to add additional information? '):
		x = input('Enter name of new key: ')
		pw_info[x] = input('Enter {}: '.format(x))
	pw_dic[name] = {'info': pw_info}
	set_pw(name, pw)

def delete_pw_line(name):
	if _yes_no_question('Do you really want to delete {!s}? '.format(name)):
		del pw_dic[name]
		save_dic()

def copy_pw_line(name):
	new_name = input('Enter new name: ')
	if new_name in pw_dic:
		if not _yes_no_question('Name already in pw_dic, overwrite? '):
			return
	pw_dic[new_name] = pw_dic[name].copy()
	save_dic()

def move_pw_line(name):
	new_name = input('Enter new name: ')
	if new_name in pw_dic and not _yes_no_question('Name already in pw_dic, overwrite? '):
		return
	pw_dic[new_name] = pw_dic.pop(name)
	save_dic()

def edit_pw_line(name):
	pw_info = pw_dic[name]['info']
	print(tabulate(sorted(pw_info.items())))
	while _yes_no_question('Do you want to add / change keys? '):
		x = input('Enter name of key: ')
		y = input("Enter {!s} ('DEL' will delete the key): ".format(x))
		if y == 'DEL':
			if x in pw_info:
				del pw_info[x]
			else:
				print('key does not exist')
		else:
			pw_info[x] = y
	save_dic()


def list_pw_lines(keys=('description', 'username')):
	'''Show all password lines with keys, default: description and username
	To show all available info call list_pw_lines(None)
	'''
	if not keys:
		keys = tuple(sorted(set(k for v in pw_dic.values() for k in v['info'])))
	elif isinstance(keys, str):
		keys = (keys,)
	arr = tuple((name,) + tuple(val['info'].get(k, '') for k in keys)
			for name, val in sorted(pw_dic.items()))
	print(tabulate(arr, headers=(('name',) + keys)))


def check_lifetimes():
	now = int(utc_ts())
	to_update = tuple(name for name, v in pw_dic.items() if v['update_ts'] < now)
	if not (to_update and _yes_no_question('There are passwords to renew. Renew them now? ')):
		return
	for name in to_update:
		if _yes_no_question('The lifetime of {!s} expired. Do you want to change the password? '.format(name)):
			change_pw(name)
		elif _yes_no_question('Do you want to extend the lifetime? '):
			pw_dic[name]['update_ts'] = now + pw_lifetime()
			save_dic()

#-------------------------------------------------------

if __name__ == '__main__':
	if os.path.exists(FILENAME):
		read_dic()
		check_lifetimes()
	elif _yes_no_question("File '{!s}' not found, create a new password file? ".format(FILENAME)):
		pw_dic = {}
		change_mpw()
