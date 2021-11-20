# type: ignore
import argparse
import logging
try:
    import tkinter
    from tkinter.simpledialog import askstring
    from tkinter import messagebox
except ImportError:
    tkinter = None


def ask_pass(primary_message, secondary_message=None):
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    root = tkinter.Tk()
    root.withdraw()
    password = askstring('SSH-MITM - Askpass', dialog_text, show="*")
    if password is not None:
        return password
    return None


def confirm(primary_message, secondary_message=None):
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    root= tkinter.Tk()
    answer = tkinter.messagebox.askquestion('SSH-MITM - Askpass', dialog_text, icon='question')
    if answer == 'yes':
        return True
    return False


def main():
    if tkinter is None:
        logging.error("tkinter not installed!")
        sys.exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument('messages', nargs='*')
    args = parser.parse_args()

    lines = " ".join(args.messages).split("\n")
    primary_message = lines[0].strip()
    if primary_message == "":
        primary_message = "ssh-askpass"

    secondary_message = "\n".join(lines[1:]).strip()
    if secondary_message == "":
        secondary_message = None

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
