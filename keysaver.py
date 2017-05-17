#
# Copyright (c) 2017, Lugino-Emeritus (NTI)
# Version 0.1.2
#

from random import SystemRandom
sys_rand_class = SystemRandom()
def sys_randint(a, b = None):
	if b == None:
		(a, b) = (0, a)
	assert a < b
	return sys_rand_class.randint(a, b)

from hashlib import sha256
from Crypto.Cipher import AES
import Crypto.Util.Counter as CryptCount
import pyperclip
from getpass import getpass
import os
from tabulate import tabulate
import pyscrypt
import hmac

FILE_NAME = "pwDicRepr"

#pw_dic_data['name'] = {'info': {"description": "Mail Telekom Main", "username": "username"},
#                       'enc_info': {'method': 'sha256 AES', 'data': {"salt": "random salt (32 byte ?)"}},
#                       'enc_data': b'very_secret'}

# print(bytes([0xF0,0x9D,0x84,0x9e]).decode('utf-8'))

PREF_ENC_METHOD = 'sha256 AES'
PREF_GLOBAL_ENCRYPT = 'AES CTR scrypt'
PREF_CHECK_MPW = 'scrypt_1-5'

save_mpw = True
global_mpw = b''
global_key = b''

#-------------------------------------------------------

def yes_no_question(s):
	yes = set(['yes', 'y', 'j', 'ja'])
	no = set(['no', 'n', 'nein'])
	while True:
		choice = input(s).lower()
		if choice in yes:
			return True
		elif choice in no:
			return False
		else:
			print("Please respond with 'yes' or 'no'.")

#-------------------------------------------------------

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
	allowed_chars = '''!#$%&()*+,-./:;<=>?@[\]_{|}~''' #do not use all characters: ^, ', ", `
	return allowed_chars[i]

def get_char(i): # 0 <= i <= 25 + 26 + 10 + 28 = 89
	if i < 26:
		return get_lower_char(i)
	elif i < 52:
		return get_upper_char(i-26)
	elif i < 62:
		return get_number(i-52)
	elif i < 89:
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

	pw_arr[ind[0]] = get_char(sys_randint(0,25))
	pw_arr[ind[1]] = get_char(sys_randint(0,25) + 26)
	pw_arr[ind[2]] = get_char(sys_randint(0,10) + 52)
	pw_arr[ind[3]] = get_char(sys_randint(0,27) + 62)
	for i in ind[4:]:
			pw_arr[i] = get_char(sys_randint(0,89))

	return ''.join(pw_arr)

#-------------------------------------------------------

def get_salted_sha256(pw, salt = b''):
	return sha256(pw + salt).digest()

def simple_aes_encrypt(data, key):
	data += b'1' + b'0' * (16 - (len(data) + 1) % 16)
	IV = get_salt(16)
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
	IV = get_salt(16)
	mac = hmac.new(key[-16:], data, sha256).digest()[:24]
	data = mac + data
	data += b'1' + b'0' * (16 - (len(data) + 1) % 16)
	aes_obj = AES.new(key[:32], AES.MODE_CTR, counter = CryptCount.new(128, initial_value=int.from_bytes(IV, 'big')))
	return IV + aes_obj.encrypt(data)

def aes_hmac_decrypt(data, key):
	(IV, data) = (data[:16], data[16:])
	aes_obj = AES.new(key[:32], AES.MODE_CTR, counter = CryptCount.new(128, initial_value=int.from_bytes(IV, 'big')))
	data = aes_obj.decrypt(data)
	(mac, data) = (data[:24], data[24:])
	while data[-1:] == b'0':
		data = data[:-1]
	data = data[:-1]
	if mac != hmac.new(key[-16:], data, sha256).digest()[:24]:
		print('Message authentication code is wrong!!!')
		#return b''
	return data

#-------------------------------------------------------

AVAILABLE_ENC_METHODS = ['sha256 AES', 'scrypt_1 AES', 'clear', 'AES CTR scrypt']
AVAILABLE_CHECK_METHODS = ['sha256_16', 'scrypt_1-5', 'clear', 'none']

def get_salt(n):
	return bytes([sys_randint(0,255) for i in range(n)])

def encrypt_data(data, enc_info, key):
	method = enc_info['method']
	if method in ['sha256 AES', 'scrypt_1 AES']:
		return simple_aes_encrypt(data, key)
	elif method == 'clear':
		return data
	elif method == 'AES CTR scrypt':
		return aes_hmac_encrypt(data, key)
	raise KeyError('''method_type '{}' not known'''.format(method))

def decrypt_data(data, enc_info, key):
	method = enc_info['method']
	if method in ['sha256 AES', 'scrypt_1 AES']:
		return simple_aes_decrypt(data, key)
	elif method == 'clear':
		return data
	elif method == 'AES CTR scrypt':
		return aes_hmac_decrypt(data, key)
	raise KeyError('''method_type '{}' not known'''.format(method))

def expand_pw(pw, enc_info):
	method = enc_info['method']
	if method == 'sha256 AES':
		return get_salted_sha256(pw, enc_info['data']['salt'])
	elif method == 'sha256_16':
		return get_salted_sha256(pw, enc_info['data']['salt'])[-16:]
	elif method in ['scrypt_1-5', 'scrypt_1 AES', 'AES CTR scrypt']:
		args = enc_info['data']
		return pyscrypt.hash(pw, args['salt'], args['N'], args['r'], args['p'], args['dkLen'])
	elif method == 'clear':
		return pw
	elif method == 'none':
		return b'0'
	raise KeyError('''method_type '{}' not known'''.format(method))

def init_enc_info_data(method):
	if method == 'sha256 AES':
		return {'salt': get_salt(32)}
	elif method == 'sha256_16':
		return {'salt': get_salt(32)}
	elif method == 'scrypt_1 AES':
		return {'salt': get_salt(32), 'N': 2048, 'r': 2, 'p': 1, 'dkLen': 32}
	elif method == 'AES CTR scrypt':
		return {'salt': get_salt(32), 'N': 2048, 'r': 2, 'p': 2, 'dkLen': 48}
	elif method == 'scrypt_1-5':
		return {'salt': get_salt(10), 'N': 1024, 'r': 1, 'p': 1, 'dkLen': 5}
	elif method == 'clear':
		return {}
	elif method == 'none':
		return {}
	raise KeyError('''hash_method '{}' not known'''.format(method))


def read_new_pw():
	pw = b''
	while True:
		pw = getpass('Insert new password: ')
		if getpass('Insert password again: ') == pw:
			return pw.encode('utf-8')
		print('Passwords are not equal. Try it again.')

#-------------------------------------------------------

def save_changes():
	global global_key
	global save_mpw
	pw_dic_info['save_mpw'] = save_mpw
	pw_dic['info'] = pw_dic_info
	if global_key:
		pw_dic['data'] = encrypt_data(repr(pw_dic_data).encode('utf-8'), pw_dic_info['global_encrypt'], global_key)
	else:
		pw_dic['data'] = pw_dic_data
	open(FILE_NAME, "w").write(repr(pw_dic))


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
			print('Master password wrong, insert it again')
		mpw = getpass('Insert master password: ').encode('utf-8')
		first_round = False

	if save_mpw:
		global_mpw = mpw
	else:
		global_mpw = b''

	return mpw

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
		input('Click Enter to continue. ')
		print('Old Password needed.')
		old_mpw = get_mpw()
		print('New master password:')
		new_mpw = read_new_pw()

		if yes_no_question('Do you want to change the method using to check the master password? '):
			print('Available: {}'.format(', '.join(AVAILABLE_CHECK_METHODS)))
			method = input('Insert method: ')
			while method not in AVAILABLE_CHECK_METHODS:
				method = input('Method not know, try it again: ')
			check_mpw['method'] = method

		if yes_no_question('Do you want to change the encryption method? '):
			print('Available: {}'.format(', '.join(AVAILABLE_ENC_METHODS)))
			method = input('Insert method: ')
			while method not in AVAILABLE_ENC_METHODS:
				method = input('Method not know, try it again: ')
			pw_dic_info['pref_method'] = method

		check_mpw['data'] = init_enc_info_data(check_mpw['method'])

		for name in pw_dic_data:
			update_pass_pw_line(name, old_mpw, new_mpw = new_mpw)
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

def add_global_key(mpw = b'', new_method = '', ask = True):
	global global_key
	if not mpw:
		mpw = get_mpw()
	enc_info = pw_dic_info['global_encrypt']

	if new_method:
		if new_method in AVAILABLE_ENC_METHODS:
			enc_info['method'] = new_method
		else:
			print("add_global_key: method '{}' not known. Use '{}' instead.".format(enc_info['method'], enc_info['method']))
		
	if ask and yes_no_question('Do you want to change the global encryption method? '):
		print('Available: {}'.format(', '.join(AVAILABLE_ENC_METHODS)))
		method = input('Insert method: ')
		while method not in AVAILABLE_ENC_METHODS:
			method = input('Method not know, try it again: ')
		enc_info['method'] = method
		
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

#-------------------------------------------------------

def get_pw(name, mpw = b''):
	x = pw_dic_data[name]
	if not mpw:
		mpw = get_mpw()
	return decrypt_data(x['enc_data'], x['enc_info'], expand_pw(mpw, x['enc_info']))

def add_pw_line(pw_len = 0):
	pw_line = {}
	pw_line['enc_info'] = {'method': pw_dic_info['pref_method'], 'data': {}}

	pw_line['enc_info']['data'] = init_enc_info_data(pw_line['enc_info']['method'])
	key = expand_pw(get_mpw(), pw_line['enc_info'])

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
	pw_line['enc_data'] = encrypt_data(pw, pw_line['enc_info'], key)

	pw_line['info'] = {'description': description, 'username': username}
	pw_dic_data[name] = pw_line

	while yes_no_question('Do you want to add additional information? '):
		x = input('Insert name of additional data: ')
		pw_dic_data[name]['info'][x] = input('Insert ' + x + ': ')

	save_changes()


def delete_pw_line(name):
	if yes_no_question('Do you really want to delete \'' + name + '\'? '):
		del pw_dic_data[name]
		save_changes()

def list_pw_lines(keys = ['description', 'username']):
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

def copy_pw_line(name):
	new_name = input('Insert new name: ')
	if new_name in pw_dic_data:
		if not yes_no_question('Name already in pw_dic, overwrite? '):
			return
	pw_dic_data[new_name] = pw_dic_data[name]
	save_changes()

def edit_pw_line(name, keys = []): #keys: Array like ['description', 'username', 'password']
	if isinstance(keys, str):
		keys = [keys]
	for x in keys:
		if x == 'name':
			new_name = input('Insert new name: ')
			if new_name in pw_dic_data:
				if not yes_no_question('Name already in pw_dic, overwrite? '):
					return
			pw_dic_data[new_name] = pw_dic_data[name]
			del pw_dic_data[name]
			name = new_name
		else:
			if x not in pw_dic_data[name]['info']:
				print('value \'' + x + '\' is not defined yet. This will add the value.')
			s = input('Insert ' + x + ': ')
			if s == 'delete!' and  x in pw_dic_data[name]['info']:
				del pw_dic_data[name]['info'][x]
				print('value ' + x + ' deleted.')
			else:
				pw_dic_data[name]['info'][x] = s
		save_changes()

def update_pass_pw_line(name, mpw, new_mpw = b'', new_pw = b'', new_method = ''):
	pw_line = pw_dic_data[name]
	if not new_pw:
		new_pw = get_pw(name, mpw)
	if not new_mpw:
		new_mpw = mpw
	if not new_method:
		new_method = pw_dic_info['pref_method']

	pw_line['enc_info']['method'] = new_method

	pw_line['enc_info']['data'] = init_enc_info_data(pw_line['enc_info']['method'])
	key = expand_pw(new_mpw, pw_line['enc_info'])

	pw_line['enc_data'] = encrypt_data(new_pw, pw_line['enc_info'], key)

	pw_dic_data[name] = pw_line
	save_changes()

def change_pw(name, pw_len = 0):
	if yes_no_question('This would change the password of \'' + name + "'. Continue? "):
		if pw_len > 4:
			pw = get_random_pw(pw_len).encode('utf-8')
			if yes_no_question('Auto created new password, copy to clipboard? '):
				pyperclip.copy(pw.decode('utf-8'))
		else:
			pw = read_new_pw()
		update_pass_pw_line(name, get_mpw(), new_pw = pw)

def auto_save_mpw(save = None):
	global save_mpw, global_mpw
	if save == None:
		if save_mpw:
			save = yes_no_question('Master password saved automatically. Should it also be saved in future? ')
		else:
			save = yes_no_question('Master password not saved automatically. Should it be saved in future? ')
	save_mpw = save
	if not save_mpw:
		global_mpw = b''
	save_changes()

#-------------------------------------------------------

if os.path.exists(FILE_NAME):
	pw_dic = eval(open(FILE_NAME).read())
	pw_dic_info = pw_dic['info']
	save_mpw = pw_dic_info['save_mpw']
	if pw_dic_info['global_encrypt']['method']:
		global_key = expand_pw(get_mpw(), pw_dic_info['global_encrypt'])
		pw_dic_data = eval(decrypt_data(pw_dic['data'], pw_dic_info['global_encrypt'], global_key).decode('utf-8'))
	else:
		pw_dic_data = pw_dic['data']
else:
	pw_dic = {}
	pw_dic_info = {'save_mpw':  False, 'pref_method': PREF_ENC_METHOD, 'check_mpw': {'method': PREF_CHECK_MPW, 'hash': b'', 'data': {'salt': b''}}, 'global_encrypt': {'method': PREF_GLOBAL_ENCRYPT, 'data': {'salt': b''}}}
	pw_dic_data = {}
	print('New File was created, now you have to add a master password.')
	set_mpw()
	add_global_key(ask = False)
	print('Global key added.')
	if yes_no_question('Do you want to add the first password line? '):
		add_pw_line()
	save_mpw = False
	global_mpw = b''
	save_changes()