import argparse
import logging
from typing import NoReturn, Optional, Text

from typeguard import typechecked
try:
    import tkinter
    from tkinter.simpledialog import askstring
    from tkinter import ttk
    tkinter_imported = True
except ImportError:
    tkinter_imported = False


@typechecked
def ask_pass(primary_message: Text, secondary_message: Optional[Text] = None) -> Optional[Text]:
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    password = askstring('SSH-MITM - Askpass', dialog_text, show="*")
    if password is not None:
        return password
    return None


@typechecked
def confirm(primary_message: Text, secondary_message: Optional[Text] = None) -> bool:
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    answer = tkinter.messagebox.askquestion('SSH-MITM - Askpass', dialog_text, icon='question')  # type: ignore
    if answer == 'yes':
        return True
    return False


def main() -> NoReturn:
    if not tkinter_imported:
        logging.error("tkinter not installed!")
        exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument('messages', nargs='*')
    args = parser.parse_args()

    lines = " ".join(args.messages).split("\n")
    primary_message = lines[0].strip()
    if primary_message == "":
        primary_message = "ssh-askpass"

    secondary_message: Optional[Text] = "\n".join(lines[1:]).strip()
    if secondary_message == "":
        secondary_message = None

    root = tkinter.Tk()
    root.withdraw()
    style = ttk.Style()
    style.theme_use('clam')
    if primary_message.endswith("?"):
        ok = confirm(primary_message, secondary_message)
        if not ok:
            exit(1)
    else:
        result = ask_pass(primary_message, secondary_message)
        if result is None:
            exit(1)
        else:
            print(result)
    exit(0)


if __name__ == '__main__':
    main()
