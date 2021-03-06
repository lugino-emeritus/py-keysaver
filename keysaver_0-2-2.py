'''
Copyright (c) Lugino-Emeritus (NTI)
Version 0.2.2
'''
import Crypto.Util.Counter as CryptCount
import hmac
import os
import pyscrypt
import pyperclip
import time
from cryptography.hazmat.backends import default_backend as hazmat_def_backend
from cryptography.hazmat.primitives.ciphers import (
	Cipher as HazmatCipher, algorithms as hazmat_algorithms, modes as hazmat_modes)
from Crypto.Cipher import AES
from getpass import getpass
from hashlib import sha256
from random import SystemRandom
from tabulate import tabulate

FILE_NAME = "pwDicRepr"

PREF_ENC_METHOD = 'scrypt_1 XOR32'
ALT_ENC_METHOD = 'AES GCM scrypt'
PREF_GLOBAL_ENCRYPT = 'AES GCM scrypt'
PREF_CHECK_MPW = 'scrypt_1-5'
PREF_PASSWORD_LIFETIME = 365 * 24 * 60 * 60

save_mpw = True
global_mpw = b''
global_key = b''

# pw_dic_data['name'] = {'info': {"description": "Mail Telekom Main", "username": "username"},
#                        'enc_info': {'method': 'sha256 AES', 'data': {"salt": "random salt (32 byte ?)"}},
#                        'enc_data': b'very_secret'}

#-------------------------------------------------------

def yes_no_question(s):
	yes = frozenset({'yes', 'y', 'j', 'ja'})
	no = frozenset({'no', 'n', 'nein'})
	while True:
		choice = input(s).lower()
		if choice in yes:
			return True
		elif choice in no:
			return False
		else:
			print("Please respond with 'yes' or 'no'.")

def read_new_pw():
	pw = b''
	while True:
		pw = getpass('Enter new password: ')
		if getpass('Enter password again: ') == pw:
			return pw.encode('utf-8')
		print('Passwords are not equal. Try it again.')

#-------------------------------------------------------

sys_rand_class = SystemRandom()
def sys_randint(a, b=None):
	'''returns random integer n with a <= n <= b'''
	if b is None:
		(a, b) = (0, a)
	assert a < b
	return sys_rand_class.randint(a, b)

def get_lower_char(i):
	assert 0 <= i <= 25
	return chr(97 + i)

def get_upper_char(i):
	assert 0 <= i <= 25
	return chr(65 + i)

def get_number(i):
	assert 0 <= i <= 9
	return str(i)

def get_symbol(i): #0 <= i <= 27
	allowed_chars = r'''!#$%&()*+,-./:;<=>?@[\]_{|}~'''  # do not use all characters: ^, ', ", `
	return allowed_chars[i]

def get_char(i): # 0 <= i <= 25 + 26 + 10 + 28 = 89
	if i < 26:
		return get_lower_char(i)
	elif i < 52:
		return get_upper_char(i-26)
	elif i < 62:
		return get_number(i-52)
	elif i < 90:
		return get_symbol(i-62)
	return ' '

def get_random_pw(n):
	if n < 4:
		print("Password too short!")
		return ''
	pw_arr = [''] * n

	ind = list(range(n))

	for i in range(n-1):
		k = sys_randint(i, n-1)
		(ind[i], ind[k]) = (ind[k], ind[i])

	pw_arr[ind[0]] = get_lower_char(sys_randint(0, 25))
	pw_arr[ind[1]] = get_upper_char(sys_randint(0, 25))
	pw_arr[ind[2]] = get_number(sys_randint(0, 9))
	pw_arr[ind[3]] = get_symbol(sys_randint(0, 27))
	for i in ind[4:]:
		pw_arr[i] = get_char(sys_randint(0, 89))

	return ''.join(pw_arr)

#-------------------------------------------------------

def b_list_xor(b1, b2):
	if len(b2) > len(b1):
		(b1, b2) = (b2, b1)
	b2 += bytes(len(b1) - len(b2))
	return bytes(a^b for a, b in zip(b1, b2))

def get_salted_sha256(pw, salt=b''):
	return sha256(pw + salt).digest()

def simple_aes_encrypt(data, key):
	data += b'1' + b'0' * (16 - (len(data) + 1) % 16)
	IV = os.urandom(16)
	aes_obj = AES.new(key, AES.MODE_CBC, IV)
	return IV + aes_obj.encrypt(data)

def simple_aes_decrypt(data, key):
	(IV, data) = (data[:16], data[16:])
	aes_obj = AES.new(key, AES.MODE_CBC, IV)
	data = aes_obj.decrypt(data)
	while data[-1:] == b'0':
		data = data[:-1]
	return data[:-1]

# use same key for hmac (sha256) and aes, first create hmac (reduced to 24 bit), then encrypt hmac|message
def aes_hmac_encrypt(data, key): #optimal key length: 48 byte, at least 32 byte
	IV = os.urandom(16)
	mac = hmac.new(key[-16:], data, sha256).digest()[:24]
	data = mac + data
	data += b'1' + b'0' * (16 - (len(data) + 1) % 16)
	aes_obj = AES.new(key[:32], AES.MODE_CTR, counter=CryptCount.new(128, initial_value=int.from_bytes(IV, 'big')))
	return IV + aes_obj.encrypt(data)

def aes_hmac_decrypt(data, key):
	(IV, data) = (data[:16], data[16:])
	aes_obj = AES.new(key[:32], AES.MODE_CTR, counter=CryptCount.new(128, initial_value=int.from_bytes(IV, 'big')))
	data = aes_obj.decrypt(data)
	(mac, data) = (data[:24], data[24:])
	while data[-1:] == b'0':
		data = data[:-1]
	data = data[:-1]
	if mac != hmac.new(key[-16:], data, sha256).digest()[:24]:
		print('Message authentication code is wrong!!!')
		return b''
	return data

def aes_gcm_encrypt(data, key):
	iv = os.urandom(16)
	encryptor = HazmatCipher(
		hazmat_algorithms.AES(key),
		hazmat_modes.GCM(iv),
		backend=hazmat_def_backend()
		).encryptor()
	data = encryptor.update(data) + encryptor.finalize()
	assert len(encryptor.tag) == 16
	return iv + encryptor.tag + data

def aes_gcm_decrypt(data, key):
	(iv, tag, data) = (data[:16], data[16:32], data[32:])
	decryptor = HazmatCipher(
		hazmat_algorithms.AES(key),
		hazmat_modes.GCM(iv, tag),
		backend=hazmat_def_backend()
		).decryptor()
	data = decryptor.update(data) + decryptor.finalize()
	return data

#-------------------------------------------------------

AVAILABLE_ENC_METHODS = ['sha256 AES', 'scrypt_1 AES', 'clear', 'AES CTR scrypt', 'scrypt_1 XOR32', 'AES GCM scrypt']
AVAILABLE_CHECK_METHODS = ['sha256_16', 'scrypt_1-5', 'clear', 'none']

def encrypt_data(data, enc_info, key):
	method = enc_info['method']
	if method in ['sha256 AES', 'scrypt_1 AES']:
		return simple_aes_encrypt(data, key)
	elif method == 'clear':
		return data
	elif method == 'AES CTR scrypt':
		return aes_hmac_encrypt(data, key)
	elif method == 'scrypt_1 XOR32':
		if len(data) > 32:
			raise AssertionError('data longer than 32 bytes; choose different encryption method')
		return b_list_xor(data, key)
	elif method == 'AES GCM scrypt':
		return aes_gcm_encrypt(data, key)
	raise KeyError('''method_type '{}' unknown'''.format(method))

def decrypt_data(data, enc_info, key):
	method = enc_info['method']
	if method in ['sha256 AES', 'scrypt_1 AES']:
		return simple_aes_decrypt(data, key)
	elif method == 'clear':
		return data
	elif method == 'AES CTR scrypt':
		return aes_hmac_decrypt(data, key)
	elif method == 'scrypt_1 XOR32':
		if len(data) > 32:
			raise AssertionError('data longer than 32 bytes?!')
		x = b_list_xor(data, key)
		while x[-1] == 0:
			x = x[:-1]
		return x
	elif method == 'AES GCM scrypt':
		return aes_gcm_decrypt(data, key)
	raise KeyError('''method_type '{}' not known'''.format(method))

def expand_pw(pw, enc_info):
	method = enc_info['method']
	if method == 'sha256 AES':
		return get_salted_sha256(pw, enc_info['data']['salt'])
	elif method == 'sha256_16':
		return get_salted_sha256(pw, enc_info['data']['salt'])[-16:]
	elif method in ['scrypt_1-5', 'scrypt_1 AES', 'AES CTR scrypt', 'scrypt_1 XOR32', 'AES GCM scrypt']:
		args = enc_info['data']
		return pyscrypt.hash(pw, args['salt'], args['N'], args['r'], args['p'], args['dkLen'])
	elif method == 'clear':
		return pw
	elif method == 'none':
		return b'0'
	raise KeyError('''method_type '{}' not known'''.format(method))

def init_enc_info_data(method):
	if method == 'sha256 AES':
		return {'salt': os.urandom(32)}
	elif method == 'sha256_16':
		return {'salt': os.urandom(32)}
	elif method in ['scrypt_1 AES', 'scrypt_1 XOR32']:
		return {'salt': os.urandom(32), 'N': 2048, 'r': 2, 'p': 1, 'dkLen': 32}
	elif method == 'AES CTR scrypt':
		return {'salt': os.urandom(32), 'N': 2048, 'r': 2, 'p': 2, 'dkLen': 48}
	elif method == 'scrypt_1-5':
		return {'salt': os.urandom(10), 'N': 1024, 'r': 1, 'p': 1, 'dkLen': 5}
	elif method == 'AES GCM scrypt':
		return {'salt': os.urandom(32), 'N': 2048, 'r': 2, 'p': 1, 'dkLen': 32}
	elif method == 'clear':
		return {}
	elif method == 'none':
		return {}
	raise KeyError('''hash_method '{}' not known'''.format(method))

def get_valid_enc_method(enc_method=None):
	while enc_method not in AVAILABLE_ENC_METHODS:
		if enc_method:
			print('Encryption method {} is not available, please choose different one.'.format(enc_method))
		else:
			print('Choose encryption method:')
		print('(available: {})'.format(', '.join(AVAILABLE_ENC_METHODS)))
		enc_method = input('Enter method: ')
	return enc_method

#-------------------------------------------------------

def save_changes():
	global global_key, save_mpw
	pw_dic_info['save_mpw'] = save_mpw
	pw_dic['info'] = pw_dic_info
	if global_key:
		pw_dic['data'] = encrypt_data(repr(pw_dic_data).encode('utf-8'), pw_dic_info['global_encrypt'], global_key)
	else:
		pw_dic['data'] = pw_dic_data
	open(FILE_NAME, "w").write(repr(pw_dic))

def encrypt_metadata(data, enc_method=None, mpw=None):
	if enc_method:
		enc_method = get_valid_enc_method(enc_method)
	else:
		enc_method = pw_dic_info['pref_method']
	alt_method_used = False
	if not mpw:
		mpw = get_mpw()
	while True:
		enc_info = {'method': enc_method, 'data': {}}
		enc_info['data'] = init_enc_info_data(enc_info['method'])
		key = expand_pw(mpw, enc_info)
		try:
			enc_data = encrypt_data(data, enc_info, key)
			return (enc_data, enc_info)
		except AssertionError:
			print('Method {} is not available to encrypt your data.'.format(enc_method))

		if not alt_method_used:
			enc_method = pw_dic_info.get('alt_method', None)
		else:
			enc_method = None
		if enc_method is None:
			print('Choose alternative method.')
			enc_method = get_valid_enc_method()
		else:
			print('using alternative method: {}'.format(enc_method))


def get_pw(name, mpw=b''):
	x = pw_dic_data[name]
	if not mpw:
		mpw = get_mpw()
	return decrypt_data(x['enc_data'], x['enc_info'], expand_pw(mpw, x['enc_info']))

def get_mpw():
	global global_mpw, save_mpw

	mpw = global_mpw
	check_mpw = pw_dic_info['check_mpw']
	pw_hash = check_mpw['hash']
	if not pw_hash:
		raise ValueError('Master password not set yet.')

	first_round = True
	while pw_hash != expand_pw(mpw, check_mpw) or not mpw:
		if not first_round:
			print('Master password wrong, try it again')
		mpw = getpass('Enter master password: ').encode('utf-8')
		first_round = False

	if save_mpw:
		global_mpw = mpw
	else:
		global_mpw = b''

	return mpw

def update_pass_pw_line(name, mpw, new_mpw=b'', new_pw=b'', new_method=''):
	pw_line = pw_dic_data[name]
	if not new_pw:
		new_pw = get_pw(name, mpw)
	if not new_mpw:
		new_mpw = mpw
	if not new_method:
		new_method = pw_dic_info['pref_method']

	(pw_line['enc_data'], pw_line['enc_info']) = encrypt_metadata(new_pw, enc_method=new_method, mpw=new_mpw)
	pw_dic_data[name] = pw_line
	save_changes()


def check_pw_lifetimes():
	skip = False
	for name in pw_dic_data:
		if time.time() > pw_dic_data[name].get('update_ts', 0):
			print('')
			if not skip:
				if yes_no_question('There are passwords to renew. Renew them now? '):
					skip = True
				else:
					return False
			if yes_no_question('The lifetime of {} was expired. Do you want to change the password now? '.format(name)):
				print('Old / current login data:')
				show_pw(name)
				if yes_no_question('Do you want to autocreate a new password? '):
					print('Length of new password (at least 6):')
					while True:
						try:
							pw_len = int(input())
							if pw_len < 6:
								raise ValueError
							break
						except ValueError:
							print('Value not a valid integer, try it again:')
					change_pw(name, pw_len)
				else:
					change_pw(name)
			else:
				if 'lifetime' not in pw_dic_info:
					pw_dic_info['lifetime'] = PREF_PASSWORD_LIFETIME
				if yes_no_question('Do you want to extend the lifetime ({:0.1f} days)? '.format(pw_dic_info['lifetime'] / (60 * 60 * 24))):
					pw_dic_data[name]['update_ts'] = time.time() + pw_dic_info['lifetime']
	if skip:
		save_changes()
		return True
	return False

#-------------------------------------------------------

def set_mpw():
	global global_mpw, save_mpw, global_key
	mpw = global_mpw
	check_mpw = pw_dic_info['check_mpw']
	if not check_mpw['hash']:
		check_mpw['data'] = init_enc_info_data(check_mpw['method'])
		print('New master password needed.')
		mpw = read_new_pw()
	else:
		if not yes_no_question('This would change your master password. Continue? '):
			return
		print('It is really recommend to make a backup of your data file now.')
		input('Click enter to continue. ')
		print('Old Password needed.')
		old_mpw = get_mpw()
		print('New master password:')
		new_mpw = read_new_pw()

		if yes_no_question('Do you want to change the method using to check the master password? '):
			print('Available: {}'.format(', '.join(AVAILABLE_CHECK_METHODS)))
			method = input('Enter method: ')
			while method not in AVAILABLE_CHECK_METHODS:
				method = input('Method not know, try it again: ')
			check_mpw['method'] = method

		if yes_no_question('Do you want to change the encryption method? '):
			pw_dic_info['pref_method'] = get_valid_enc_method()
		if yes_no_question('Do you want to change the alternative encryption method? '):
			pw_dic_info['alt_method'] = get_valid_enc_method()
		check_mpw['data'] = init_enc_info_data(check_mpw['method'])

		for name in pw_dic_data:
			update_pass_pw_line(name, old_mpw, new_mpw=new_mpw)
		mpw = new_mpw

	check_mpw['hash'] = expand_pw(mpw, check_mpw)
	pw_dic_info['check_mpw'] = check_mpw
	if global_key:
		add_global_key(mpw)
	if save_mpw:
		global_mpw = mpw
	else:
		global_mpw = b''
	save_changes()

def auto_save_mpw(save=None):
	global save_mpw, global_mpw
	if save is None:
		if save_mpw:
			save = yes_no_question('Master password saved automatically. Should it also be saved in future? ')
		else:
			save = yes_no_question('Master password not saved automatically. Should it be saved in future? ')
	save_mpw = save
	if not save_mpw:
		global_mpw = b''
	save_changes()

def add_global_key(mpw=b'', ask=True):
	global global_key
	if not mpw:
		mpw = get_mpw()
	enc_info = pw_dic_info['global_encrypt']

	if ask and yes_no_question('Do you want to change the global key method? '):
		enc_info['method'] = get_valid_enc_method()

	enc_info['data'] = init_enc_info_data(enc_info['method'])

	global_key = expand_pw(mpw, enc_info)

	pw_dic_info['global_encrypt'] = enc_info
	save_changes()

def remove_global_key():
	global global_key
	if global_key and yes_no_question('Are you sure you want to remove the global key? '):
		pw_dic_info['global_encrypt']['data'] = {}
		pw_dic_info['global_encrypt']['method'] = ''
		global_key = b''
		save_changes()


def add_pw_line(pw_len=0, enc_method=None):
	pw_line = {}
	name = input('Name: ')
	if name in pw_dic_data:
		if not yes_no_question('Name already in pw_dic, overwrite? '):
			return
	description = input('Description: ')
	username = input('Username: ')
	if pw_len > 4:
		pw = get_random_pw(pw_len).encode('utf-8')
		if yes_no_question('Auto created password, copy to clipboard? '):
			pyperclip.copy(pw.decode('utf-8'))
	else:
		pw = read_new_pw()

	(pw_line['enc_data'], pw_line['enc_info']) = encrypt_metadata(pw, enc_method=enc_method)
	pw_line['info'] = {'description': description, 'username': username}
	while yes_no_question('Do you want to add additional information? '):
		x = input('Enter name of additional data: ')
		pw_line['info'][x] = input('Enter {}: '.format(x))
	pw_line['update_ts'] = time.time() + pw_dic_info.get('lifetime', PREF_PASSWORD_LIFETIME)
	pw_dic_data[name] = pw_line
	save_changes()

def delete_pw_line(name):
	if yes_no_question('Do you really want to delete \'' + name + '\'? '):
		del pw_dic_data[name]
		save_changes()

def list_pw_lines(keys=['description', 'username']):
	arr = []
	if isinstance(keys, str):
		if keys == 'all':
			keys = []
			for name in pw_dic_data:
				for x in pw_dic_data[name]['info']:
					if x not in keys:
						keys.append(x)
			keys = sorted(keys)
		else:
			keys = [keys]
	for x in pw_dic_data:
		arr.append([x] + [pw_dic_data[x]['info'][i] if i in pw_dic_data[x]['info'] else '' for i in keys])
	arr = sorted(arr, key=lambda x: x[0])
	print(tabulate(arr, headers=(['name'] + keys)))


def show_pw(name):
	pw = get_pw(name)
	print('username: ' + pw_dic_data[name]['info']['username'] + ', password: ' + pw.decode('utf-8'))

def copy_pw(name):
	pw = get_pw(name)
	pyperclip.copy(pw.decode('utf-8'))
	print('username: ' + pw_dic_data[name]['info']['username'] + ', password copied.')

def change_pw(name, pw_len=0):
	if yes_no_question('This would change the password of \'' + name + "'. Continue? "):
		if pw_len > 4:
			pw = get_random_pw(pw_len).encode('utf-8')
			if yes_no_question('Auto created new password, copy to clipboard? '):
				pyperclip.copy(pw.decode('utf-8'))
		else:
			pw = read_new_pw()
		pw_dic_data[name]['update_ts'] = time.time() + pw_dic_info.get('lifetime', PREF_PASSWORD_LIFETIME)
		update_pass_pw_line(name, get_mpw(), new_pw=pw)

def set_pw_lifetime(lifetime=0):
	if lifetime == 0:
		try:
			lifetime = 24 * 60 * 60 * float(input('Enter lifetime of new passwords in days: '))
		except ValueError:
			print('Lifteime not valid.')
			return
	if lifetime < 0:
		lifetime = PREF_PASSWORD_LIFETIME
	pw_dic_info['lifetime'] = lifetime
	save_changes()


def copy_pw_line(name):
	new_name = input('Enter new name: ')
	if new_name in pw_dic_data:
		if not yes_no_question('Name already in pw_dic, overwrite? '):
			return
	pw_dic_data[new_name] = pw_dic_data[name]
	save_changes()

def edit_pw_line(name, keys=[]): #keys: Array like ['description', 'username', 'password']
	if isinstance(keys, str):
		keys = [keys]
	for x in keys:
		if x == 'name':
			new_name = input('Enter new name: ')
			if new_name in pw_dic_data:
				if not yes_no_question('Name already in pw_dic, overwrite? '):
					return
			pw_dic_data[new_name] = pw_dic_data[name]
			del pw_dic_data[name]
			name = new_name
		else:
			if x not in pw_dic_data[name]['info']:
				print('value \'{}\' is not defined yet. This will add the value.'.format(x))
			s = input('Enter {}:'.format(x))
			if s == 'delete!' and  x in pw_dic_data[name]['info']:
				del pw_dic_data[name]['info'][x]
				print('value ' + x + ' deleted.')
			else:
				pw_dic_data[name]['info'][x] = s
		save_changes()

#-------------------------------------------------------

if __name__ == '__main__':
	if os.path.exists(FILE_NAME):
		pw_dic = eval(open(FILE_NAME).read())
		pw_dic_info = pw_dic['info']
		org_save_mpw = pw_dic_info['save_mpw']
		save_mpw = True
		if pw_dic_info['global_encrypt']['method']:
			global_key = expand_pw(get_mpw(), pw_dic_info['global_encrypt'])
			pw_dic_data = eval(decrypt_data(pw_dic['data'], pw_dic_info['global_encrypt'], global_key).decode('utf-8'))
		else:
			pw_dic_data = pw_dic['data']
		if check_pw_lifetimes() and not org_save_mpw:
			auto_save_mpw(False)
		elif not org_save_mpw:
			save_mpw = False
			global_mpw = b''
	else:
		pw_dic = {}
		pw_dic_info = {
			'save_mpw':  False, 'pref_method': PREF_ENC_METHOD, 'alt_method': ALT_ENC_METHOD,
			'check_mpw': {'method': PREF_CHECK_MPW, 'hash': b'', 'data': {'salt': b''}},
			'global_encrypt': {'method': PREF_GLOBAL_ENCRYPT, 'data': {'salt': b''}}
			}
		pw_dic_data = {}
		print('New File was created, now you have to add a master password.')
		set_mpw()
		add_global_key(ask=False)
		print('Global key added.')
		if yes_no_question('Do you want to add the first password line? '):
			add_pw_line()
		save_mpw = False
		global_mpw = b''
		save_changes()


def convert_pw_dic():
	import keysaver as ks
	print('converting pw_dic for keysaver 0.3.0')
	mpw = get_mpw()
	print('CONVERTING...')
	pw_dic1 = {}
	for name, val in pw_dic_data.items():
		pw_dic1[name] = {'info': val['info'], 'update_ts': int(val['update_ts'])}
		pw_dic1[name]['enc_data'] = get_pw(name, mpw=mpw)
	ks.pw_dic = pw_dic1
	ks.change_mpw()
	print('DONE')
	exit()
