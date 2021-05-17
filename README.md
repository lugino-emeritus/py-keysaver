# Python KeySaver

This is a small tool to create random passwords and save them encrypted.
A master password is used to encrypt the data.


#### Dependencies:

- python 3.6 or newer
- argon2 `pip install argon2-cffi`
- msgpack `pip install msgpack`
- pyperclip `pip install pyperclip`
- tabulate `pip install tabulate`
- `ntlib.fctthread` from [ntlib](https://github.com/lugino-emeritus/py-ntlib)


## Usage

Start the script with `python -i keysaver.py [<pwdic>]`. It will open or create an encrypted file `<pwdic>` where your passwords will be stored.

After 5 minutes without interaction you have to enter the master password again.


### Commands

The following commands are probably self-explanatory. `name` is the name of a password-line.

- `add_pw_line(name)`
- `delete_pw_line(name)`
- `copy_pw_line(name)`: duplicate the pw_line
- `move_pw_line(name)`: rename the pw_line
- `edit_pw_line(name)`: modify additional informations
- `list_pw_lines(keys=('description', 'username'))`: shows names and info for all saved password-lines. `keys=None` will show all keywords.
- `pw_info(name)`: show all information assigned to `name`
- `show_pw(name, info=False)`
- `copy_pw(name, info=False)`
- `change_pw(name)`

To change the master password call `change_mpw()`.


### Some technical details

The file is encrypted with AES256 GCM if using method `\x00\x01` (default setting). Method `\x00\x00` does not encrypt and is only for debugging.

To expand the master password to the AES key argon2id is used (512 MiB RAM). The master password is never saved.

Moreover each password itself is encrypted using AES CBC and a token derived from the master password. After a random value of 400 to 600 days without changing a password you will be asked whether you want to change it.

Each time you open and save the file (automatically done by e.g. adding or changing a password) a new salt is created.
