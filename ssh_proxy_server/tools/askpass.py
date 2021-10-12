import argparse
import logging
try:
    import wx
except ImportError:
    wx = None


def ask_pass(primary_message, secondary_message=None):
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    app = wx.App()
    dlg = wx.PasswordEntryDialog(None, dialog_text, 'SSH-MITM - Askpass', "", wx.OK | wx.CANCEL)

    response = dlg.ShowModal()
    if response == wx.ID_OK:
        return dlg.GetValue()
    return None


def confirm(primary_message, secondary_message=None):
    dialog_text = primary_message
    if secondary_message:
        dialog_text = "\n".join([primary_message, secondary_message])
    app = wx.App()
    dlg = wx.MessageDialog(None, dialog_text, 'SSH-MITM - Askpass', wx.YES | wx.NO)
    response = dlg.ShowModal()
    if response == wx.ID_YES:
        return True
    return False


def main():
    if wx is False:
        logging.error("wxPython not installed! please install!")
        exit(1)

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
