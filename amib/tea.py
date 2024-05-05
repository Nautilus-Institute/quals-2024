import ctypes
import struct


def _decipher(v, k):
    """
    TEA decipher algorithm.  Decodes a length-2 vector using a length-4 vector as a length-2 vector.

    Compliment of _encipher.
    :param v:
        A vector representing the information to be deciphered.  *Must* have a length of 2.
    :param k:
        A vector representing the encryption key.  *Must* have a length of 4.
    :return:
        The original message.
    """
    y, z = [ctypes.c_uint32(x) for x in v]
    sum = ctypes.c_uint32(0xC6EF3720)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        z.value = z.value - (((y.value << 4 ^ y.value >> 5) + y.value) ^ (sum.value + k[sum.value >> 11 & 3]))
        sum.value -= delta
        y.value = y.value - (((z.value << 4 ^ z.value >> 5) + z.value) ^ (sum.value + k[sum.value & 3]))

    return [y.value, z.value]

def main():
    flag = b"flag{HpxULe0jdmc?t=705_3QzfrWsnRU3WKMfk}"
    print(len(flag))

    key_str = b"-=Calaquendi44=-"
    print("Initial key:")
    print(", ".join([str(x) for x in key_str]))

    data = b""
    for i in range(0, len(flag), 8):
        key_v = [struct.unpack("<I", key_str[i:i+4])[0] for i in range(0, 16, 4)]

        chunk0 = struct.unpack("<I", flag[i:i+4])[0]
        chunk1 = struct.unpack("<I", flag[i+4:i+8])[0]
        decrypted = _decipher([chunk0, chunk1], key_v)
        data += struct.pack("<I", decrypted[0])
        data += struct.pack("<I", decrypted[1])

        # mess with the key
        key_str = bytes([(ch + j) ^ 0xcc for j, ch in enumerate(key_str)])

    print("Data:")
    print(", ".join([str(x) for x in data]))
    breakpoint()

    # load machine bytes from the binary
    bin_path = r"amib-core.exe"
    with open(bin_path, "rb") as f:
        data = f.read()
    start_offset = data.find(b"\x90" * 5) + 5
    end_offset = data.rfind(b"\x90" * 5)
    shellcode = data[start_offset : end_offset]

    import binascii
    print(binascii.hexlify(shellcode))


if __name__ == "__main__":
    main()
