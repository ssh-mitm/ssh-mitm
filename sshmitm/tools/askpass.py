"""
SSH-MITM Askpass

This is a Python implementation of the SSH-ASKPASS utility which provides a simple
Tkinter-based GUI dialog to obtain a password from the user.

This utility is often used in conjunction with the OpenSSH ssh-agent program to
securely store private keys. The ssh-agent program is able to hold private keys in
memory, and automatically provides the passphrases required to use these keys.
When a key is added to the ssh-agent, it is encrypted and stored in memory, and
ssh-askpass is used to prompt the user for the passphrase required to unlock the key.

This module provides a GUI dialog to obtain a password from the user, as well as a
function to confirm a question with a yes/no answer. The module requires Tkinter to
be installed to function. If Tkinter is not installed, a error message will be logged
and the program will exit with exit code 1.

The main() function is the entry point for the application, and takes an argument list of
messages, which are used as the primary and secondary messages to be displayed in the dialog.
If the first message ends with a question mark, the confirm() function is used, otherwise the
ask_pass() function is used. If the user cancels or closes the dialog,
the program will exit with exit code 1.
"""

import argparse
import logging
import sys
from typing import NoReturn, Optional

try:
    import tkinter
    from tkinter.simpledialog import askstring
    from tkinter import ttk
    TKINTER_IMPORTED = True
except ImportError:
    TKINTER_IMPORTED = False


def ask_pass(primary_message: str, secondary_message: Optional[str] = None) -> Optional[str]:
    """
    This function displays a dialog box for the user to enter a password.
     The dialog box has a primary message, and an optional secondary message.

    :param primary_message: The primary message to be displayed in the dialog box
    :type primary_message: str
    :param secondary_message: An optional secondary message to be displayed in the dialog box
    :type secondary_message: Optional[str]
    :return: The password entered by the user
    :rtype: Optional[str]
    """
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    password = askstring('SSH-MITM - Askpass', dialog_text, show="*")
    if password is not None:
        return password
    return None


def confirm(primary_message: str, secondary_message: Optional[str] = None) -> bool:
    """
    Confirms a question with yes or no answer.

    :param primary_message: The main message to be displayed
    :type primary_message: str
    :param secondary_message: An optional secondary message to be displayed
    :type secondary_message: Optional[str]
    :return: True if answer is yes, False otherwise.
    :rtype: bool
    """
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    answer = tkinter.messagebox.askquestion('SSH-MITM - Askpass', dialog_text, icon='question')  # type: ignore
    if answer == 'yes':
        return True
    return False


def main() -> NoReturn:
    """
    Main function to run the SSH-ASKPASS implementation.
    """
    if not TKINTER_IMPORTED:
        logging.error("tkinter not installed!")
        sys.exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument('messages', nargs='*')
    args = parser.parse_args()

    lines = " ".join(args.messages).split("\n")
    primary_message = lines[0].strip()
    if primary_message == "":
        primary_message = "ssh-askpass"

    secondary_message: Optional[str] = "\n".join(lines[1:]).strip()
    if secondary_message == "":
        secondary_message = None

    root = tkinter.Tk()
    root.withdraw()
    style = ttk.Style()
    style.theme_use('clam')
    if primary_message.endswith("?"):
        rvalue_ok = confirm(primary_message, secondary_message)
        if not rvalue_ok:
            sys.exit(1)
    else:
        result = ask_pass(primary_message, secondary_message)
        if result is None:
            sys.exit(1)
        else:
            print(result)
    sys.exit(0)


if __name__ == '__main__':
    main()
