import binascii


def format_hex(data: bytes, hexwidth: int = 19) -> str:
    """
    Format the data in hexadecimal format.

    :param data: Data to be formatted
    :param hexwidth: Width of hexadecimal data (default 19)
    :return: Formatted hexadecimal data
    """
    result = []
    for i in range(0, len(data), hexwidth):
        data_part = data[i : i + hexwidth]
        hexa = list(
            map(
                "".join,
                zip(*[iter(binascii.hexlify(data_part).decode("utf-8"))] * 2),
            )
        )
        while hexwidth - len(hexa) > 0:
            hexa.append(" " * 2)
        text = "".join([chr(x) if 0x20 <= x < 0x7F else "." for x in data_part])
        addr = "%04X:    %s    %s" % (  # pylint: disable=consider-using-f-string
            i,
            " ".join(hexa),
            text,
        )
        result.append(addr)

    return "\n".join(result)
