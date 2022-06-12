import cmd
import crc_bruteforce
import crc_bruteforce_simos85
import can
from can import Message
import lz4.block
import math
from tqdm import tqdm
import struct
import time
import pigpio
import subprocess
from udsoncan.connections import IsoTPSocketConnection
import socket
import logging

timestr = time.strftime("%Y%m%d-%H%M%S")
logging.basicConfig(level=logging.INFO, filename="logfile_{}".format(timestr), filemode="a+",
                        format="%(asctime)-15s %(levelname)-8s %(message)s")

TWISTER_PATH = (
    "Simos8_SBOOT/twister"
)  # This is the path to the "twister" binary from https://github.com/fastboatster/Simos8_SBOOT.git

# Configurable parameters:

# For a Pi 3B+, 0.0005 seems right. For a Pi 4, 0.0008 has been observed to work correctly (presumably latency between sleep and GPIO is lower).
CRC_DELAY = (
    0.00005
)  # This is the amount of time a single iteration of the CRC process takes. This will need to be adjusted through observation, checking the output of the boot password read process until 0x100 bytes are being checked.

#TODO make this dependent on the ecu reset timestamp and seed message timestamp. I.e., the amount of time which passed
# between the reset and received seed message
SEED_START = (
    # "1D00000" # for Simos 18
    "1800000"  # for Simos 8.5
)  # This is the starting value for the expected timer value range for the Seed/Key calculation. This seems to work for both Pi 3B+ and Pi 4.

# number of `None` messages after `6B` request after which we'll ignore missing `A0` response
# and try to go into the ISO-TP shell anyway (given that we got  `A0` response to the initial `59 45` request)
NONE_MSG_CNT_THRESHOLD = 60

sector_map_tc1791 = {  # Sector lengths for PMEM routines
    0: 0x4000,
    1: 0x4000,
    2: 0x4000,
    3: 0x4000,
    4: 0x4000,
    5: 0x4000,
    6: 0x4000,
    7: 0x4000,
    8: 0x20000,
    9: 0x40000,
    10: 0x40000,
    11: 0x40000,
    12: 0x40000,
    13: 0x40000,
    14: 0x40000,
    15: 0x40000,
}


def bits(byte):
    bit_arr = [
        (byte >> 7) & 1,
        (byte >> 6) & 1,
        (byte >> 5) & 1,
        (byte >> 4) & 1,
        (byte >> 3) & 1,
        (byte >> 2) & 1,
        (byte >> 1) & 1,
        (byte) & 1,
    ]
    bit_arr.reverse()
    return bit_arr


def print_success_failure(data):
    if data is not None:
        if data[0] is 0xA0:
            print("Success")
        else:
            print("Failure! " + data.hex())
    else:
        print("Empty data")


def get_key_from_seed(seed_data):

    p = subprocess.run(
        [TWISTER_PATH, SEED_START, seed_data, "1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output_data = p.stdout.decode("us-ascii")
    return output_data

# can interface to use, RPi is weird sometimes and only creates can1
#can_interface = "can0"
can_interface = "can1"
bus = can.interface.Bus(can_interface, bustype="socketcan")
pi = pigpio.pi()
pi.set_mode(23, pigpio.OUTPUT)
pi.set_pull_up_down(23, pigpio.PUD_UP)

# deactivate HWCFG pins - set to high impedance values:
#pi.set_mode(24, pigpio.INPUT)
#pi.set_pull_up_down(24, pigpio.PUD_OFF)

# pi.set_mode(24, pigpio.OUTPUT)
# pi.set_pull_up_down(24, pigpio.PUD_UP)
# pi.write(24, 1)
# pi.set_mode(25, pigpio.OUTPUT)
# pi.set_pull_up_down(25, pigpio.PUD_DOWN)
# pi.write(25, 0)

# pi.set_mode(25, pigpio.INPUT)
# pi.set_pull_up_down(25, pigpio.PUD_OFF)


def get_isotp_conn():
    conn = IsoTPSocketConnection(
        can_interface, rxid=0x7E8, txid=0x7E0, params={"tx_padding": 0x55}
        # "can0", rxid=0x7E8, txid=0x7E0, params={"tx_padding": 0x55}
    )
    conn.tpsock.set_opts(txpad=0x55)
    conn.open()
    return conn


def sboot_pwm():
    import time
    import wavePWM

    GPIO = [12, 13]

    if not pi.connected:
        exit(0)

    pwm = wavePWM.PWM(pi)  # Use default frequency

    pwm.set_frequency(3210)
    # pwm.set_frequency(6420)
    cl = pwm.get_cycle_length()
    pwm.set_pulse_start_in_micros(13, cl / 1)
    pwm.set_pulse_length_in_micros(13, cl / 2)

    pwm.set_pulse_start_in_micros(12, 3 * cl / 4)
    pwm.set_pulse_length_in_micros(12, cl / 4)
    pwm.update()
    return pwm

# reset_ecu as used in local RPi script, wonder if `pi.set_pull_up_down(23, pigpio.PUD_DOWN)`
# and pi.set_pull_up_down(23, pigpio.PUD_UP) were causing long reset times
# def reset_ecu():
#     # old reset:
# #     pi.write(23, 0)
# #     time.sleep(0.01)
# #     pi.write(23, 1)
#     # try to do it differently:
#     # set the pin to pull down mode:
#     pi.set_pull_up_down(23, pigpio.PUD_DOWN)
#     # may need to write 1 or 0:
#     pi.write(23, 0)
#     time.sleep(0.01)
#     # pi.write(23, 0)
#     pi.set_pull_up_down(23, pigpio.PUD_UP)
#     pi.write(23, 1)


def reset_ecu():
    pi.write(23, 0)
    time.sleep(0.01)
    pi.write(23, 1)


def sboot_getseed():
    conn = get_isotp_conn()
    print("Sending 0x30 to elevate SBOOT shell status...")
    conn.send(bytes([0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
    print_success_failure(conn.wait_frame())
    time.sleep(1)
    print("Sending 0x54 Generate Seed...")
    conn.send(bytes([0x54]))
    data = conn.wait_frame()
    print_success_failure(data)
    first_frame = data[:9]
    print("First CAN frame for seed response:\n")
    print(first_frame)
    dt = data[9:]
    conn.close()
    return dt


def sboot_sendkey(key_data):
    conn = get_isotp_conn()
    send_data = bytearray([0x65])
    send_data.extend(key_data)
    print("Sending 0x65 Security Access with Key...")
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    conn.close()


def sboot_crc_reset_simos8(crc_start_address):
    prepare_upload_bsl()
    conn = get_isotp_conn()
    print("Setting initial CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting expected CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC range count to 1...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print(
        "Setting start CRC start address to boot passwords at " + crc_start_address.hex() + "..."
    )
    send_data = bytearray([0x78, 0x00, 0x00, 0x00, 0x0C])
    # convert crc start address from big to little endian:
    send_data.extend(int.from_bytes(crc_start_address, "big").to_bytes(4, "little"))
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC end address to a valid area at 0xD40000B0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x10, 0xB0, 0x00, 0x00, 0xD4])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Uploading valid part number for part correlation validator...")
    send_data = bytes(
        [
            0x78,
            0x00,
            0x00,
            0x00,
            0x14,
            0x4e,
            0x42,
            0x30,
            0x65,
            0x00,
            0x00,
            0x53,
            0x38,
            0x35,
            0x32,
            0x31,
            0x2d,
            0x36,
            0x35,
            0x30,
            0x53,
            0x38,
            0x35,
            0x35,
            0x32,
            0x30,
            0x35,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
        ]
    )

    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Starting Validator and rebooting into BSL...")
    conn.send(bytes([0x79]))
    time.sleep(CRC_DELAY)
    upload_bsl(True)
    crc_address = int.from_bytes(read_byte_simos8(0xc03fd488.to_bytes(4, "big")), "little")
    print("CRC Address Reached: ")
    print(hex(crc_address))
    crc_data = int.from_bytes(read_byte_simos8(0xc03fd490.to_bytes(4, "big")), "little")
    print("CRC32 Current Value: ")
    print(hex(crc_data))
    conn.close()
    return (crc_address, crc_data)


# this is from simos18
def sboot_crc_reset(crc_start_address):
    prepare_upload_bsl()
    conn = get_isotp_conn()
    print("Setting initial CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting expected CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC range count to 1...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print(
        "Setting start CRC start address to boot passwords at "
        + crc_start_address.hex()
        + "..."
    )
    send_data = bytearray([0x78, 0x00, 0x00, 0x00, 0x0C])
    send_data.extend(int.from_bytes(crc_start_address, "big").to_bytes(4, "little"))
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC end address to a valid area at 0xb0010130...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x10, 0x30, 0x01, 0x01, 0xB0])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Uploading valid part number for part correlation validator...")
    send_data = bytes(
        [
            0x78,
            0x00,
            0x00,
            0x00,
            0x14,
            0x4E,
            0x42,
            0x30,
            0xD1,
            0x00,
            0x00,
            0x53,
            0x43,
            0x38,
            0x34,
            0x30,
            0x2D,
            0x31,
            0x30,
            0x32,
            0x36,
            0x31,
            0x39,
            0x39,
            0x31,
            0x41,
            0x41,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
        ]
    )
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Starting Validator and rebooting into BSL...")
    conn.send(bytes([0x79]))
    time.sleep(CRC_DELAY)
    upload_bsl(True)
    crc_address = int.from_bytes(read_byte(0xD0010770 .to_bytes(4, "big")), "little")
    print("CRC Address Reached: ")
    print(hex(crc_address))
    crc_data = int.from_bytes(read_byte(0xD0010778 .to_bytes(4, "big")), "little")
    print("CRC32 Current Value: ")
    print(hex(crc_data))
    conn.close()
    return (crc_address, crc_data)


def sboot_shell():
    print("Setting up PWM waveforms...")
    pwm = sboot_pwm()
    time.sleep(1)
    print("Resetting ECU into Supplier Bootloader...")
    print("Please turn on ECU power...")
    input("Press Enter to continue...")
    # not using automatic ecu reset yet, reset manually by switching the power on and off
    # reset_ecu()
    
    print("Sending 59 45...")
    # might need to try to receive A0 first:
    fd = open('log.txt', 'a')
    fd.write("Sending 59 45...\n")
    bus.send(Message(data=[0x59, 0x45], arbitration_id=0x7E0, is_extended_id=False))
    message = bus.recv(0.05)  
    bus.send(Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False))
    fd.write('Sending 0x6b\n')
    stage2 = False

    while True:
        if stage2 is True:
            bus.send(Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False))
            print("Sending 6B...")
            fd.write('Sending 6B...\n')
        message = bus.recv(0.01)
        print(message)
        if message is not None:
            fd.write(str(message.arbitration_id) + ": ")
            fd.write(message.data.hex())
            fd.write('\n')
        if (
            message is not None
            and message.arbitration_id == 0x7E8
            and message.data[0] == 0xA0
        ):
            print("Got A0 message")
            fd.write("Got A0 message\n")
            if stage2:
                print("Switching to IsoTP Socket...")
                fd.write("Switching to IsoTP Socket...\n")
                pwm.cancel()
                return sboot_getseed()
            print("Sending 6B...")
            fd.write("Sending 6B...")
            stage2 = True
        if message is not None and message.arbitration_id == 0x0A7:
            print("FAILURE")
            fd.write("FAILURE\n")
            pwm.cancel()
            return False


def sboot_shell_test():
    # this version of sboot_shell is ignoring missing A0 response to 6B,
    # switches to ISO-TP socket after a while anyway
    print("Setting up PWM waveforms...")
    pwm = sboot_pwm()
    time.sleep(1)
    print("Resetting ECU into Supplier Bootloader...")
    print("Please turn on ECU power...")
    input("Press Enter to continue...")
    reset_ecu()

    print("Sending 59 45...")
    # might need to try to receive A0 first:
    fd = open('log.txt', 'a')
    fd.write("Sending 59 45...\n")
    bus.send(Message(data=[0x59, 0x45], arbitration_id=0x7E0, is_extended_id=False))
    # message = bus.recv(0.05)
    bus.send(Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False))
    fd.write('Sending 0x6b\n')
    stage2 = False
    # set the counter for None messages after 6B was sent.
    # We'll try to ignore missed positive response msg after a certain number of None messages
    # and proceed to the next step anyway:
    none_msg_counter = 0

    while True:
        if stage2 is True:
            bus.send(Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False))
            print("Sending 6B...")
            fd.write('Sending 6B...\n')
        message = bus.recv(0.05)
        print(message)
        if message is None:
            none_msg_counter += 1
        if none_msg_counter > NONE_MSG_CNT_THRESHOLD:
                print("Haven't gotten a CAN message in a while, just proceed...\n")
                print("Switching to IsoTP Socket...\n")
                fd.write("Switching to IsoTP Socket...\n")
                pwm.cancel()
                return sboot_getseed()
        if message is not None:
            fd.write(str(message.arbitration_id) + ": ")
            fd.write(message.data.hex())
            fd.write('\n')
        if (
            message is not None
            and message.arbitration_id == 0x7E8
            and message.data[0] == 0xA0
        ):
            print("Got A0 message")
            fd.write("Got A0 message\n")
            if stage2:
                print("Switching to IsoTP Socket...")
                fd.write("Switching to IsoTP Socket...\n")
                pwm.cancel()
                return sboot_getseed()
            # print("Sending 6B...")
            # fd.write("Sending 6B...")
            stage2 = True
        if message is not None and message.arbitration_id == 0x0A7:
            print("FAILURE")
            fd.write("FAILURE\n")
            pwm.cancel()
            return False


def sboot_login():
    sboot_seed = sboot_shell_test()
    # sboot_seed = sboot_shell()
    print("Calculating key for seed: ")
    print(sboot_seed.hex())
    key = get_key_from_seed(sboot_seed.hex()[0:8])
    print("Key calculated : ")
    print(key)
    sboot_sendkey(bytearray.fromhex(key))


def extract_boot_passwords():
    addresses = map(
        lambda x: bytearray.fromhex(x), ["8001420C", "80014210", "80014214", "80014218"]
    )
    crcs = []
    for address in addresses:
        sboot_login()
        end_address, crc = sboot_crc_reset(address)
        print(address.hex() + " - " + hex(end_address) + " -> " + hex(crc))
        crcs.append(hex(crc))
    boot_passwords = crc_bruteforce.calculate_passwords(crcs)
    print(boot_passwords.hex())


def extract_boot_passwords_simos8():
    addresses = map(
        lambda x: bytearray.fromhex(x), ["8001420C", "80014210", "80014214", "80014218"]
    )
    crcs = []  # contains crc vals and range lens
    for address in addresses:
        sboot_login()
        end_address, crc = sboot_crc_reset_simos8(address)
        start_address = int.from_bytes(address, "big")
        crc_range_len = end_address - start_address
        print(address.hex() + " - " + hex(end_address) + " - " + hex(crc_range_len) + " -> " + hex(crc))
        crcs.append((hex(crc), hex(crc_range_len)))
    boot_passwords = crc_bruteforce_simos85.calculate_passwords(crcs)
    print(boot_passwords.hex())


def prepare_upload_bsl():
    # this was for Simos 18
    # Pin 24 -> BOOT_CFG pin, pulled to GND to enable BSL mode.
    #     print("Resetting ECU into HWCFG BSL Mode...")
    #     pi.set_mode(24, pigpio.OUTPUT)
    #     pi.set_pull_up_down(24, pigpio.PUD_DOWN)
    #     pi.write(24, 0)
    # attempt to set HWCFG for Simos 8 in automated way
    # conf 1 - tried, doesn't work
#     print("Resetting ECU into HWCFG BSL Mode...")
#     pi.set_mode(24, pigpio.OUTPUT)
#     pi.set_pull_up_down(24, pigpio.PUD_UP)
#     pi.write(24, 1)
#
#     pi.set_mode(25, pigpio.OUTPUT)
#     pi.set_pull_up_down(25, pigpio.PUD_DOWN)
#     pi.write(25, 0)

    #print("Resetting ECU into HWCFG BSL Mode...")
#     pi.set_mode(24, pigpio.OUTPUT)
#     pi.set_pull_up_down(24, pigpio.PUD_DOWN)
#     pi.write(24, 0)
#
#     pi.set_mode(25, pigpio.OUTPUT)
#     pi.set_pull_up_down(25, pigpio.PUD_UP)
#     pi.write(25, 1)
    # decided to manually ground/apply voltage to HWCFG pins via swithces
    print("Resetting ECU into HWCFG BSL Mode...")
    print("Please flip the switches to ground/power ECU HWCFG pins...")
    input("Press Enter to continue...")


# this now works only with Simos 8
def upload_bsl(skip_prep=False):
    if skip_prep == False:
        prepare_upload_bsl()
    reset_ecu()
    time.sleep(0.1)
#     pi.set_mode(24, pigpio.INPUT)
#     pi.set_pull_up_down(24, pigpio.PUD_OFF)
#
#     pi.set_mode(25, pigpio.INPUT)
#     pi.set_pull_up_down(25, pigpio.PUD_OFF)

    print("Sending BSL initialization message...")
    # send bootloader.bin to CAN BSL in Tricore
    #bootloader_data = open("chopped_tc1796_bl.bin", "rb").read()
    bootloader_data = open("read32.bin", "rb").read()
    #bootloader_data = open("CANLoader.bin", "rb").read()
    print(bootloader_data[0:8])
    data = [
        0x55,
        0x55,
        0x00,
        0x01,
    ]  # 0x55 0x55 bit sync, 0x100 CAN ID for ACK (copied directly to MOAR register, so lower 2 bits are discarded, this will yield actual 0x40 CAN ID)
    data += struct.pack("<H", math.ceil(len(bootloader_data) / 8))
    data += [0x0, 0x3]  # 0x300 CAN ID for Data -> 0xC0 after right shift
    init_message = Message(
        is_extended_id=False, dlc=8, arbitration_id=0x100, data=data
    )  # 0x55 0x55 = magic for init, 0x00 0x1 = 0x100 CAN ID, 0x1 0x0 = 1 packet data, 0x00, 0x3 = 0x300 transfer data can id
    success = False
    # print("Sending actual BSL initialization message...")
    print(init_message)
    bus.send(init_message)
    while success == False:
        message = bus.recv(0.5)
        if message is not None:
            print(message)
        if message is not None and not message.is_error_frame:
            if message.arbitration_id == 0x40:
                success = True
    print("Sending BSL data...")
    num_messages = int(len(bootloader_data) / 8)
    print("Number of bytes to send {}".format(len(bootloader_data)))
    print("Number of messages to send {}".format(num_messages))
    i = 0
    for block_base_address in tqdm(
        range(0, len(bootloader_data), 8), unit_scale=True, unit="blocks"
    ):
        block_end = min(len(bootloader_data), block_base_address + 8)
        message = Message(
            is_extended_id=False,
            dlc=8,
            arbitration_id=0xC0,
            data=bootloader_data[block_base_address:block_end],
        )
        bus.send(message, timeout=5)
        time.sleep(0.001)
    print("Device jumping into BSL... Draining receive queue...")
    while bus.recv(0.01) is not None:
        pass


# from simos18
def read_device_id():
    message = Message(
        is_extended_id=False,
        dlc=8,
        arbitration_id=0x300,
        data=[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    )
    bus.send(message)
    device_id = bytearray()
    message = bus.recv()
    if message.data[0] == 0x1:
        device_id += message.data[2:8]
    message = bus.recv()
    if message.data[0] == 0x1 and message.data[1] == 0x1:
        device_id += message.data[2:8]
    return device_id


def read_byte(byte_specifier):
    data = bytearray([0x02])
    data += byte_specifier
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    byte_data = bytearray()
    message = bus.recv()
    if message.data[0] == 0x2:
        byte_data += message.data[1:5]
    return byte_data


def read_byte_simos8(byte_specifier):
    data = bytearray([0x00, 0x08])
    data += byte_specifier
    data += bytearray([0x00, 0x00])
    # need to add checksum:
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0xc0, data=data)
    # print(message)
    bus.send(message)

    data2 = bytearray([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    # calc val of the last (checksum) byte
    crc_byte = 0
    header_data = data + data2
    for i in range(15):
        crc_byte = crc_byte ^ header_data[i]
    crc_byte = crc_byte.to_bytes(2, 'big')[1]
    data2+= bytearray([crc_byte])
    #this is to check that checksum check is working:
    #data2+= bytearray([0xdb])
    #print(crc_byte)
    #message2 = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data2)
    #message2 = Message(is_extended_id=False, dlc=8, arbitration_id=0x03, data=data2)
    message2 = Message(is_extended_id=False, dlc=8, arbitration_id=0xc0, data=data2)
    #print(message2)
    bus.send(message2)
    byte_data = bytearray()
    message = bus.recv(5.0)
    if message is not None:
        #print(message)
        # temporary, need to have opcode byte set
        byte_data += message.data[0:4]

    return byte_data


def simos8_can_frame_test():
    # should return 0xdeadbeef 0xbaadd00d
    data = bytearray([0x00, 0x3E])
    data += bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # need to add checksum:
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0xc0, data=data)
    # print(message)
    bus.send(message)

    data2 = bytearray([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    crc_byte = 0
    header_data = data + data2
    for i in range(15):
        crc_byte = crc_byte ^ header_data[i]
    crc_byte = crc_byte.to_bytes(2, 'big')[1]
    data2 += bytearray([crc_byte])
    message2 = Message(is_extended_id=False, dlc=8, arbitration_id=0xc0, data=data2)
    #print(message2)
    bus.send(message2)
    byte_data = bytearray()

    message = bus.recv()
    if message is not None:
        print(message)
        # temporary, need to have opcode byte set
        byte_data += message.data
    return byte_data


def write_byte(addr, value):
    data = bytearray([0x03])
    data += addr
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    byte_data = bytearray()
    message = bus.recv()
    if message.data[0] != 0x3:
        return False
    data = bytearray([0x03])
    data += value
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    if message.data[0] != 0x3:
        return False
    else:
        return True


def calc_chksum(header_data):
    crc_byte = 0
    for i in range(15):
        crc_byte = crc_byte ^ header_data[i]
    crc_byte = crc_byte.to_bytes(2, 'big')[1]
    return crc_byte


# only simos18
def send_passwords(pw1, pw2, ucb=0, read_write=0x8):
    data = bytearray([0x04])
    data += pw1
    data += bytearray([read_write, ucb, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    byte_data = bytearray()
    message = bus.recv()
    print(message)
    data = bytearray([0x04])
    data += pw2
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    print(message)
    data = bytearray([0x04])
    data += pw1
    data += bytearray([read_write, ucb, 0x1])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    byte_data = bytearray()
    message = bus.recv()
    print(message)
    data = bytearray([0x04])
    data += pw2
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    print(message)


def simos8_send_passwords(pw1, pw2, ucb=0x00, read_write=0x0):
    # form the first CAN message:
    data = bytearray([0x00, 0x10])
    data += pw1
    # add first half of the pw2
    data += pw2[:2]
    message1 = Message(is_extended_id=False, dlc=8, arbitration_id=0xc0, data=data)
    print(message1)
    bus.send(message1)

    data_msg2 = bytearray()
    data_msg2 += pw2[2:]
    # 0x00 for the flash base addr 0xA0000000, read_write is protection type, BSL will choose
    # correct type itself. 0x0 is for reading, 0x01 is for writing:
    data_msg2 += bytearray([0x00, read_write, ucb, 0x00, 0x00])
    # add crc for message1 + message2 as a last byte:
    crc_byte = 0
    header_data = data + data_msg2
    for i in range(15):
        crc_byte = crc_byte ^ header_data[i]
    crc_byte = crc_byte.to_bytes(2, 'big')[1]
    data_msg2 += bytearray([crc_byte])

    message2 = Message(is_extended_id=False, dlc=8, arbitration_id=0xc0, data=data_msg2)
    print(message2)
    bus.send(message2)
    # supposed to get 0x55 00 00 00 FF FF FF FF
    message = bus.recv()
    print(message)


def erase_sector(address):
    data = bytearray([0x05])
    data += address
    data += bytearray([0, 0, 0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()


def print_enabled_disabled(string, value):
    enabled_or_disabled = "ENABLED" if value > 0 else "DISABLED"
    print(string + " " + enabled_or_disabled)


# simos18 for now
def print_sector_status(string, procon_sector_status):
    current_address = 0
    for sector_number in sector_map_tc1791:
        protection_status = procon_sector_status[sector_number]
        if sector_number > 9:
            protection_status = procon_sector_status[
                math.ceil(
                    sector_number - (sector_number % 2) - (sector_number - 10) / 2
                )
            ]
        if protection_status > 0:
            print(
                string
                + "Sector "
                + str(sector_number)
                + " "
                + hex(current_address)
                + ":"
                + hex((current_address + sector_map_tc1791[sector_number]))
                + " : "
                + "ENABLED"
            )

        current_address += sector_map_tc1791[sector_number]


def read_flash_properties(flash_num, pmu_base_addr):
    FSR = 0x1010
    FCON = 0x1014
    PROCON0 = 0x1020
    PROCON1 = 0x1024
    PROCON2 = 0x1028
    fsr_value = read_byte(struct.pack(">I", pmu_base_addr + FSR))
    fcon_value = read_byte(struct.pack(">I", pmu_base_addr + FCON))
    procon0_value = read_byte(struct.pack(">I", pmu_base_addr + PROCON0))
    procon1_value = read_byte(struct.pack(">I", pmu_base_addr + PROCON1))
    procon2_value = read_byte(struct.pack(">I", pmu_base_addr + PROCON2))
    pmem_string = "PMEM" + str(flash_num)
    flash_status = bits(fsr_value[2])
    print_enabled_disabled(pmem_string + " Protection Installation: ", flash_status[0])
    print_enabled_disabled(
        pmem_string + " Read Protection Installation: ", flash_status[2]
    )
    print_enabled_disabled(pmem_string + " Read Protection Inhibit: ", flash_status[3])
    print_enabled_disabled(pmem_string + " Write Protection User 0: ", flash_status[5])
    print_enabled_disabled(pmem_string + " Write Protection User 1: ", flash_status[6])
    print_enabled_disabled(pmem_string + " OTP Installation: ", flash_status[7])

    flash_status_write = bits(fsr_value[3])
    print_enabled_disabled(
        pmem_string + " Write Protection User 0 Inhibit: ", flash_status_write[1]
    )
    print_enabled_disabled(
        pmem_string + " Write Protection User 1 Inhibit: ", flash_status_write[2]
    )

    protection_status = bits(fcon_value[2])
    print_enabled_disabled(pmem_string + " Read Protection: ", protection_status[0])
    print_enabled_disabled(
        pmem_string + " Disable Code Fetch from Flash Memory: ", protection_status[1]
    )
    print_enabled_disabled(
        pmem_string + " Disable Any Data Fetch from Flash: ", protection_status[2]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from DMA Controller: ", protection_status[4]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from PCP Controller: ", protection_status[5]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from SHE Controller: ", protection_status[6]
    )
    procon0_sector_status = bits(procon0_value[0]) + bits(procon0_value[1])
    print_sector_status(pmem_string + " USR0 Read Protection ", procon0_sector_status)
    procon1_sector_status = bits(procon1_value[0]) + bits(procon1_value[1])
    print_sector_status(pmem_string + " USR1 Write Protection ", procon1_sector_status)
    procon2_sector_status = bits(procon2_value[0]) + bits(procon2_value[1])
    print_sector_status(pmem_string + " USR2 OTP Protection ", procon2_sector_status)


def read_bytes_file(base_addr, size, filename):
    output_file = open(filename, "wb")
    for current_address in tqdm(
        range(base_addr, base_addr + size, 4), unit_scale=True, unit="block"
    ):
        bytes = read_byte(struct.pack(">I", current_address))
        output_file.write(bytes)
    output_file.close()


def simos8_read_bytes_file(base_addr, size, filename):
    output_file = open(filename, "wb")
    for current_address in tqdm(
        range(base_addr, base_addr + size, 4), unit_scale=True, unit="block"
    ):
        bytes = read_byte_simos8(struct.pack(">I", current_address))
        output_file.write(bytes)
    output_file.close()


# for simos 18:
def read_compressed(address, size, filename):
    output_file = open(filename, "wb")
    data = bytearray([0x07])
    data += address
    data += size
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    total_size_remaining = int.from_bytes(size, "big")
    t = tqdm(total=total_size_remaining, unit="B")
    while total_size_remaining > 0:
        message = bus.recv()
        compressed_size = size_remaining = int.from_bytes(message.data[5:8], "big")
        # print("Waiting for compressed data of size: " + hex(size_remaining))
        data = bytearray()
        sequence = 1
        while size_remaining > 0:
            message = bus.recv()
            new_sequence = message.data[1]
            if sequence != new_sequence:
                print("Sequencing error! " + hex(new_sequence) + hex(sequence))
                t.close()
                output_file.close()
                return
            sequence += 1
            sequence = sequence & 0xFF
            data += message.data[2:8]
            size_remaining -= 6
        decompressed_data = lz4.block.decompress(data[:compressed_size], 4096)
        decompressed_size = len(decompressed_data)
        t.update(decompressed_size)
        total_size_remaining -= decompressed_size
        output_file.write(decompressed_data)
        data = bytearray([0x07, 0xAC])  # send an ACk packet
        message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
        bus.send(message)
    output_file.close()
    t.close()


def simos8_read_compressed(address, size, filename):
    # right now randomly chokes sometimes and misses one message and counter gets wrong
    output_file = open(filename, "ba")
    data_msg1 = bytearray([0x00, 0x07])
    # address needs to be 4 bytes
    data_msg1 += address
    # split the size into 2 parts
    size_part1 = size[:2]
    size_part2 = size[2:]
    data_msg1 += size_part1
    message1 = Message(is_extended_id=False, dlc=8, arbitration_id=0xC0, data=data_msg1)
    bus.send(message1)
    # form second message:
    data_msg2 = bytearray(size_part2)
    data_msg2 += bytearray([0x00, 0x00, 0x00, 0x00, 0x00])
    chksum_byte = calc_chksum(data_msg1 + data_msg2)
    data_msg2 += bytearray([chksum_byte])
    message2 = Message(is_extended_id=False, dlc=8, arbitration_id=0xC0, data=data_msg2)
    bus.send(message2)
    # get ack message:
    msg = bus.recv()
    # TODO check that ack is OK:
    print(msg)

    total_size_remaining = int.from_bytes(size, "big")
    print(total_size_remaining)
    t = tqdm(total=total_size_remaining, unit="B")
    while total_size_remaining > 0:
        message = bus.recv()
        # print(message)
        compressed_size = size_remaining = int.from_bytes(message.data[5:8], "big")
        logging.info("Waiting for compressed data of size: " + hex(size_remaining))
        data = bytearray()
        sequence = 1
        while size_remaining > 0:
            message = bus.recv()
            # print(message)
            new_sequence = message.data[1]
            if sequence != new_sequence:
                print("Sequencing error! " + hex(new_sequence) + hex(sequence))
                print(message)
                logging.info("Sequencing error! " + hex(new_sequence) + hex(sequence))
                logging.info(message)
                t.close()
                output_file.close()
                return
            sequence += 1
            sequence = sequence & 0xFF
            data += message.data[2:8]
            size_remaining -= 6
            #logging.info('Size remaining: {} seq num: {}'.format(hex(size_remaining), hex(sequence)))
        decompressed_data = lz4.block.decompress(data[:compressed_size], 0x1000)
        decompressed_size = len(decompressed_data)
        t.update(decompressed_size)
        total_size_remaining -= decompressed_size
        output_file.write(decompressed_data)
        data = bytearray([0x07, 0xAC])  # send an ACk packet
        message = Message(is_extended_id=False, dlc=8, arbitration_id=0xC0, data=data)
        bus.send(message)
        logging.info('Sent data block ack message')
        msg = bus.recv()
        logging.info("Supposed to be block ack message: {}".format(msg))
    output_file.close()
    t.close()


def simos8_read_uncompressed(address, size, filename):
    output_file = open(filename, "ba")
    data_msg1 = bytearray([0x00, 0x0A])
    # address needs to be 4 bytes
    data_msg1 += address
    # split the size into 2 parts
    size_part1 = size[:2]
    size_part2 = size[2:]
    data_msg1 += size_part1
    message1 = Message(is_extended_id=False, dlc=8, arbitration_id=0xC0, data=data_msg1)
    bus.send(message1)
    # form second message:
    data_msg2 = bytearray(size_part2)
    data_msg2 += bytearray([0x00, 0x00, 0x00, 0x00, 0x00])
    chksum_byte = calc_chksum(data_msg1 + data_msg2)
    data_msg2 += bytearray([chksum_byte])
    message2 = Message(is_extended_id=False, dlc=8, arbitration_id=0xC0, data=data_msg2)
    bus.send(message2)
    # get ack message:
    msg = bus.recv()
    total_size_remaining = int.from_bytes(size, "big")
    #print(total_size_remaining)
    # TODO check that ack is OK:
    print("This is supposed to be an ack message")
    logging.info("This is supposed to be an ack message")
    print(msg)
    data = bytearray()
    # sequence = 1
    t = tqdm(total=total_size_remaining, unit="B")
    # while loop to get all the data which can consist of multiple 256B sized chunks:
    while total_size_remaining > 0:
        message = bus.recv()  # 0a a0 04 00 00 00 01 00
        # print(message)
        logging.info(message)
        chunk_size = int.from_bytes(message.data[5:8], "big")
        size_remaining = chunk_size
        # print("Waiting for the chunk of data of size: " + hex(size_remaining))
        logging.info("Waiting for the chunk of data of size: " + hex(size_remaining))
        chunk_data = bytearray()
        sequence = 1
        # current 256 B or PAGE_SIZE'd chunk
        while size_remaining > 0:
            message = bus.recv()
            # print(message)
            new_sequence = message.data[1]
            if sequence != new_sequence:
                print("Sequencing error! " + hex(new_sequence) + hex(sequence))
                logging.error("Sequencing error! " + hex(new_sequence) + hex(sequence))
                t.close()
                output_file.close()
                return
            sequence += 1
            sequence = sequence & 0xFF
            chunk_data += message.data[2:8]
            size_remaining -= 6

        # drop 0xAA filler bytes in the end:
        chunk_data = chunk_data[:chunk_size]
        output_file.write(chunk_data)
        # data += chunk_data
        size = len(chunk_data)
        # update tqdm:
        t.update(size)
        total_size_remaining -= size
        # send an ACK packet
        dt = bytearray([0x07, 0xAC])
        message = Message(is_extended_id=False, dlc=8, arbitration_id=0xC0, data=dt)
        # print('Sending ack message')
        logging.info('Sending ack message')
        bus.send(message)
        msg = bus.recv()
        # print(msg)
        logging.info(msg)

    output_file.close()


def crc_upload_test():
    sboot_login()
    addresses = list(map(
        lambda x: bytearray.fromhex(x), ["8001420C", "80014210", "80014214", "80014218"]
    ))
    prepare_upload_bsl()
    conn = get_isotp_conn()
    print("Setting initial CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting expected CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC range count to 1...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    #crc_start_address = addresses[0]
    #crc_start_address = bytearray.fromhex('80080300')
    #crc_start_address = bytearray.fromhex('80014218')
    #crc_start_address = bytearray.fromhex('80014214')
    #0x80014210
    #crc_start_address = bytearray.fromhex('80014210')
    #0x8001420C
    #crc_start_address = bytearray.fromhex('8001420C')
    # redo 80014218
    crc_start_address = bytearray.fromhex('80014218')
    #crc_start_address = bytearray.fromhex('80014300')
    print(
        "Setting start CRC start address to boot passwords at " + crc_start_address.hex() + "..."
    )
    send_data = bytearray([0x78, 0x00, 0x00, 0x00, 0x0C])
    send_data.extend(int.from_bytes(crc_start_address, "big").to_bytes(4, "little"))
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC end address to a valid area at 0xD40000B0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x10, 0xB0, 0x00, 0x00, 0xD4])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Uploading valid part number for part correlation validator...")
    send_data = bytes(
        [
            0x78,
            0x00,
            0x00,
            0x00,
            0x14,
            0x4e,
            0x42,
            0x30,
            0x65,
            0x00,
            0x00,
            0x53,
            0x38,
            0x35,
            0x32,
            0x31,
            0x2d,
            0x36,
            0x35,
            0x30,
            0x53,
            0x38,
            0x35,
            0x35,
            0x32,
            0x30,
            0x35,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
        ]
    )

    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Starting Validator and rebooting into BSL...")
    conn.send(bytes([0x79]))
    time.sleep(CRC_DELAY)
    upload_bsl(True)
    crc_address = int.from_bytes(read_byte_simos8(0xc03fd488.to_bytes(4, "big")), "little")
    print("CRC Address Reached: ")
    print(hex(crc_address))
    crc_data = int.from_bytes(read_byte_simos8(0xc03fd490.to_bytes(4, "big")), "little")
    print("CRC32 Current Value: ")
    print(hex(crc_data))
    conn.close()
    return (crc_address, crc_data)

# Enter REPL


class BootloaderRepl(cmd.Cmd):
    intro = "Welcome to Tricore BSL. Type help or ? to list commands, you are likely looking for upload to start.\n"
    prompt = "(BSL) "
    file = None

    def do_upload(self, arg):
        """Upload BSL to device"""
        upload_bsl()

    # currently 0xD000000 is overwritten by some global bootloader var, need to fix
    def do_deviceid(self, arg):
        """Read the Tricore Device ID from 0xD0000000 to 0xD000000C"""
        device_id = read_device_id()
        if len(device_id) > 1:
            print(device_id.hex())
        else:
            print("Failed to retrieve Device ID")

    def do_readaddr(self, arg):
        """readaddr <addr> : Read 32 bits from an arbitrary address"""
        byte_specifier = bytearray.fromhex(arg)
        byte = read_byte(byte_specifier)
        print(byte.hex())

    def do_readaddr_simos8(self, arg):
        """readaddr <addr> : Read 32 bits from an arbitrary address"""
        byte_specifier = bytearray.fromhex(arg)
        byte = read_byte_simos8(byte_specifier)
        print(byte.hex())

    def do_readaddr_example(self, arg):
        """readaddr <addr> : Read 32 bits from an arbitrary address"""
        # byte_specifier = bytearray.fromhex(arg)
        byte = read_byte_simos8(0xD4000C00.to_bytes(4, "big"))
        print(byte.hex())

    def do_readaddr_example2(self, arg):
        """readaddr <addr> : Read 32 bits from 0xc03fd488"""
        byte = read_byte_simos8(0xc03fd488.to_bytes(4, "big"))
        print(byte.hex())

    def do_readaddr_example3(self, arg):
        """readaddr <addr> : Read 32 bits from 0xD4000C04"""
        byte = read_byte_simos8(0xD4000C04.to_bytes(4, "big"))
        print(byte.hex())

    def do_simos8_can_test(self, arg):
        """test CAN response from bootloader"""
        byte = simos8_can_frame_test()
        print(byte.hex())

    def do_writeaddr(self, arg):
        """writeaddr <addr> <data> : Write 32 bits to an arbitrary address"""
        args = arg.split()
        byte_specifier = bytearray.fromhex(args[0])
        data_specifier = bytearray.fromhex(args[1])
        is_success = write_byte(byte_specifier, data_specifier)
        if is_success:
            print("Wrote " + args[1] + " to " + args[0])
        else:
            print("Failed to write value.")

    def do_flashinfo(self, arg):
        """Read flash information including PMEM protection status"""
        PMU_BASE_ADDRS = {0: 0xF8001000, 1: 0xF8003000}

        for pmu_num in PMU_BASE_ADDRS:
            read_flash_properties(pmu_num, PMU_BASE_ADDRS[pmu_num])

    def do_dumpmaskrom(self, arg):
        """Dump the Tricore Mask ROM to maskrom.bin"""
        read_bytes_file(0xAFFFC000, 0x4000, "maskrom.bin")

    def do_dumpmem(self, arg):
        """dumpmem <addr> <size> <filename>: Dump <addr> to <filename> with <size> bytes"""
        args = arg.split()
        read_bytes_file(int(args[0], 16), int(args[1], 16), args[2])

    def do_simos8_dumpmem(self, arg):
        """dumpmem <addr> <size> <filename>: Dump <addr> to <filename> with <size> bytes"""
        args = arg.split()
        simos8_read_bytes_file(int(args[0], 16), int(args[1], 16), args[2])

    def do_sboot(self, arg):
        """Reset into SBOOT Command Shell, execute Seed/Key process"""
        sboot_login()

    def do_crc_upload_test(self, arg):
        """Reset into SBOOT Command Shell, execute Seed/Key process and upload dummy byte data for Simos 8.5"""
        crc_upload_test()

    def do_sboot_sendkey(self, arg):
        """sboot_sendkey <keydata>: Send Key Data to SBOOT Command Shell"""
        args = arg.split()
        key_data = bytearray.fromhex(args[0])
        sboot_sendkey(key_data)

    def do_sboot_crc_reset(self, arg):
        """sboot_crc_reset <address>: Configure SBOOT with CRC header pointed to <address>, reboot"""
        args = arg.split()
        password_address = bytearray.fromhex(args[0])
        sboot_crc_reset(password_address)

    def do_send_read_passwords(self, arg):
        """send_read_passwords <pw1> <pw2>: unlock Flash using passwords"""
        args = arg.split()
        pw1 = int.from_bytes(bytearray.fromhex(args[0]), "big").to_bytes(4, "little")
        pw2 = int.from_bytes(bytearray.fromhex(args[1]), "big").to_bytes(4, "little")
        send_passwords(pw1, pw2)

    def do_send_simos8_read_passwords(self, arg):
        """send_read_passwords <pw1> <pw2>: unlock Flash using read passwords
        i.e. `send_simos8_read_passwords 53b6495b 8e1ffeb1`
        """
        args = arg.split()
        pw1 = int.from_bytes(bytearray.fromhex(args[0]), "big").to_bytes(4, "little")
        pw2 = int.from_bytes(bytearray.fromhex(args[1]), "big").to_bytes(4, "little")
        simos8_send_passwords(pw1, pw2)

    def do_send_write_passwords(self, arg):
        """send_write_passwords <pw1> <pw2>: unlock Flash using passwords"""
        args = arg.split()
        pw1 = int.from_bytes(bytearray.fromhex(args[0]), "big").to_bytes(4, "little")
        pw2 = int.from_bytes(bytearray.fromhex(args[1]), "big").to_bytes(4, "little")
        send_passwords(pw1, pw2, read_write=0x05, ucb=1)

    def do_send_simos8_write_passwords(self, arg):
        """send_write_passwords <pw1> <pw2>: unlock Flash using passwords"""
        args = arg.split()
        pw1 = int.from_bytes(bytearray.fromhex(args[0]), "big").to_bytes(4, "little")
        pw2 = int.from_bytes(bytearray.fromhex(args[1]), "big").to_bytes(4, "little")
        simos8_send_passwords(pw1, pw2, read_write=0x01, ucb=1)

    def do_erase_sector(self, arg):
        """erase_sector <addr> : Erase sector beginning with address"""
        byte_specifier = bytearray.fromhex(arg)
        erase_sector(byte_specifier)


    def do_extract_boot_passwords(self, arg):
        """extract_boot_passwords : Extract Simos18 boot passwords using SBoot exploit chain. Requires 'crchack' in
        ../crchack and 'twister' in ../Simos18_SBOOT """
        extract_boot_passwords()


    def do_extract_boot_passwords_simos8(self, arg):
        """extract_boot_passwords : Extract Simos8 boot passwords using SBoot exploit chain. Requires 'crchack' in
        ./crchack and 'twister' in ./Simos8_SBOOT """
        extract_boot_passwords_simos8()

    def do_compressed_read(self, arg):
        """compressed_read <addr> <length> <filename>: read data using LZ4 compression (fast, hopefully)"""
        args = arg.split()
        byte_specifier = bytearray.fromhex(args[0])
        length_specifier = bytearray.fromhex(args[1])
        filename = args[2]
        is_success = read_compressed(byte_specifier, length_specifier, filename)

    def do_simos8_compressed_read(self, arg):
        """Simos 8 compressed_read <addr> <length> <filename>: read data using LZ4 compression (fast, hopefully)"""
        args = arg.split()
        byte_specifier = bytearray.fromhex(args[0])
        length_specifier = bytearray.fromhex(args[1])
        filename = args[2]
        is_success = simos8_read_compressed(byte_specifier, length_specifier, filename)

    def do_simos8_uncompressed_read(self, arg):
        """Simos 8 uncompressed_read <addr> <length> <filename>: read data without any compression
        i.e. `simos8_uncompressed_read a0040000 0003FE00 uncompressed_cal_area_read.bin`
        """
        args = arg.split()
        byte_specifier = bytearray.fromhex(args[0])
        length_specifier = bytearray.fromhex(args[1])
        filename = args[2]
        is_success = simos8_read_uncompressed(byte_specifier, length_specifier, filename)

    def do_reset(self, arg):
        """reset: reset ECU"""
        reset_ecu()

    def do_bye(self, arg):
        """Exit"""
        return True

    def do_test_pwm(self, arg):
        """Test that Simos 8 goes into the service mode when PWM is applied"""
        sboot_seed = sboot_shell_test()
        print("Testing PWM, got seed: ")
        print(sboot_seed.hex())


def parse(arg):
    """Convert a series of zero or more numbers to an argument tuple"""
    return tuple(map(int, arg.split()))


BootloaderRepl().cmdloop()
