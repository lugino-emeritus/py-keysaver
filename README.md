# Python Key-Saver
This is a little script which can create random passwords and save them encrypted.
A master password is used to encrypt the data.

#### Dependencies:
* python 3.5 or newer (tested with python 3.5)
* pyperclip `pip install setuptools`, `pip install pyperclip`
* tabulate `pip install tabulate`
* pyscrypt `pip install pyscrypt`
* _other?_

Maybe it is necessary to use `pip3` instead of `pip`.

## Usage
Start the script with `python -i keysaver.py` (or `python3 -i keysaver.py`). It will create a file `pwDicRepr` with the necessary data.

### Commands:
* `list_pw_lines(keys = ['description', 'username'])`: shows names and info to all saved passwords (password-lines). `keys = 'all'` would show all keywords.
* `add_pw_line(pw_len = 0, enc_method = '')`: adds new password-line. If `pw_len > 4` a random password would be generated. `enc_method` defines a specific encryption method.
* `show_pw(name)`: shows username and password of the password-line with the name `name`.
* `copy_pw(name)`: shows username and copy password to clipboard.
---
* `change_pw(name, pw_len = 0)`: changes the password of password-line `name`. If `pw_len > 4` a random password would be generated.
* `edit_pw_line(name, keys = [])`: changes keys (not the password) of a password-line. If the key is not defined, a new key would be added. To delete a existing key insert `delete!` as value.
* `delete_pw_line(name)`: deletes password-line
* `copy_pw_line(name)`: copies a password-line
---
* `get_random_pw(n)`: returns random password (ASCII characters) with at least one upper, one lower character, one number and one symbol. The symbols `^`, `` ` ``, `'`, `` " `` and the whitespace are not used.
---
* `auto_save_mpw(save = None)`: option to save the master password, so it is only necessary to insert it when starting the script.
* `add_global_key()` or `remove_global_key()`: encrypt full data, not just password. By default a global key is active.
* `set_mpw()`: changes password and encryption method

## Some Details
### Encryption Details
To enrypt the data AES256 is used (it is possible to add other methods). To get the 32 byte long key for AES it is possible to choose between different hash methods:
* SHA256
* scrypt - much more complex compared to SHA256
* AES with CTR mode and message authentication code (hmac) is now available
* XOR32: directly xor the data with a salted hash; raise an exception if the data is too long

Only a few bytes of the hashed master password are saved to check the password. So it is possible to use 'wrong' passwords, but then the encrypted data doesn't make sense. Each password is encrypted with the master password and random salt.

### Random Data
To create random passwords random.SystemRandom is used.
