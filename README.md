# Python KeySaver
This is a small tool to create random passwords and save them encrypted.
A master password is used to encrypt the data.


### New in Version 0.3.0:
Complete redesign. To convert the old password file open the old keysaver `python -i keysaver_0-2-2.py`, then call `convert_pw_dic()`. **keysaver_0-2-2.py will be removed soon!**


#### Dependencies:
- python 3.6 or newer
- argon2 `pip install argon2-cffi`
- msgpack `pip install msgpack`
- pyperclip `pip install pyperclip`
- tabulate `pip install tabulate`
- `ntlib.fctthread`, available [here](https://github.com/lugino-emeritus/py-ntlib)


## Usage
Start the script with `python -i keysaver.py`. It will create an encrypted file `pwdic` for your future passwords. To change the filename edit the `FILENAME` constant in keysaver.py

After 5 minutes without interaction it is necessary to enter the master password again.


### Commands:
The following commands are probably self-explanatory. `name` is the name of a password-line.

- `add_pw_line(name)`
- `delete_pw_line(name)`
- `copy_pw_line(name)`: duplicate the pw_line
- `move_pw_line(name)`: rename the pw_line
- `edit_pw_line(name)`
- `list_pw_lines(keys=('description', 'username'))`: shows names and info for all saved password-lines. `keys=None` will show all keywords.
- `show_pw(name)`
- `copy_pw(name)`
- `change_pw(name)`

To change the master password call `change_mpw()`.


### Some details

The file is encrypted with AES256 GCM if using method `\x00\x01` (the default). Method `\x00\x00` does not encrpyt and is only for testing.

To expand the master password to the AES key argon2id is used (512 MiB RAM). The master password is never saved.

Moreover each password itself is encrypted using AES CBC and a token derived by the master password. After a random value of 400 to 600 days without changing a password you will be asked if you want to change it.

Each time you open and save the file (automatically done by e.g. adding or changing a pw) it uses a new salt.
