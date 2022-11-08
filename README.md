# Python KeySaver

This is a small tool to create random passwords and store them in a file (`pwdic`).
A master password is used to encrypt the data. Technical details can be found in the source.


#### Dependencies

- python3.8 or newer
- argon2 `pip install argon2-cffi`
- msgpack `pip install msgpack`
- pyperclip `pip install pyperclip`
- tabulate `pip install tabulate`
- `ntlib.fctthread` from [here](https://github.com/lugino-emeritus/py-ntlib)


## Usage

Start the script with `python3 -i keysaver.py [<pwdic>]` or `./keysaver.py [<pwdic>]`. It will open or create an encrypted file `<pwdic>` where your passwords are stored.

After 5 minutes without interaction you have to enter the master password again.

A password expires after a random time between 400 and 600 days. In that case you will be asked if you want to change it or not.


### Commands

The following commands are probably self-explanatory. `name` is the name of a password-line.

- `add_pw_line(name)`
- `delete_pw_line(name)`
- `copy_pw_line(name)`: duplicate the pw_line
- `move_pw_line(name)`: rename the pw_line
- `edit_pw_line(name)`: modify additional informations
- `list_pw_lines(keys=('description', 'username'))`: show names and info for all saved password-lines, `keys=None` will show all keywords.
- `pw_info(name)`: show all information assigned to `name`
- `show_pw(name, info=False)`
- `copy_pw(name, info=False)`
- `open_pw(name)`: open website if available and copy password to clipboard
- `change_pw(name)`

To change the master password call `change_mpw()`.
