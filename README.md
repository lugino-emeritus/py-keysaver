# Python Key-Saver
This is a little script, which can create random password and save them using AES256 and SHA256.
A master password is used to encrypt the data.

### Dependencies:
* python 3.5 or newer (tested with python 3.5)
* tabulate `pip install tabulate`
* pyscrypt `pip install pyscrypt`
* _other?_
Maybe it's necessary to use `pip3` instead of `pip`.

## Usage:
Start the script with `python -i keysaver.py` (or `python3`). It will create a file `pwDicRepr` with the necessary data.

### Commands (not complete yet):
* `list_pw_lines(values = ['description', 'username'])`: show names and info to all saved passwords. `values = 'all'` would show all keywords.
* `add_pw_line(pw_len = 0)`: add new password-line. If pw_len > 4 a random password would be generated
* `show_pw(name)`: show username and password of the password-line with the name `name`
* `copy_pw(name)`: show username and copy password to clipboard.
