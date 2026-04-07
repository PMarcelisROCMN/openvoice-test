#!/usr/bin/env python3
"""
Tries all default MIFARE keys on every sector and dumps readable blocks.
"""

import RPi.GPIO as GPIO
from mfrc522 import MFRC522

DEFAULT_KEYS = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD],
    [0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A],
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
]

reader = MFRC522()

print("Hold a card near the reader...\n")

try:
    while True:
        status, _ = reader.MFRC522_Request(reader.PICC_REQIDL)
        if status != reader.MI_OK:
            continue

        status, uid = reader.MFRC522_Anticoll()
        if status != reader.MI_OK:
            continue

        print(f"Card UID: {' '.join([hex(x) for x in uid])}\n")
        reader.MFRC522_SelectTag(uid)

        # MIFARE Classic 1K has 16 sectors, 4 blocks each = 64 blocks total
        for sector in range(16):
            for key in DEFAULT_KEYS:
                status = reader.MFRC522_Auth(
                    reader.PICC_AUTHENT1A, sector * 4 + 3, key, uid
                )
                if status == reader.MI_OK:
                    print(f"Sector {sector} — key: {' '.join([hex(x) for x in key])}")
                    for block in range(4):
                        block_num = sector * 4 + block
                        data = reader.MFRC522_Read(block_num)
                        if data:
                            raw = ' '.join([hex(x) for x in data])
                            text = ''.join([chr(x) if 32 <= x < 127 else '.' for x in data])
                            print(f"  Block {block_num}: {raw}  |  {text}")
                    break
            else:
                print(f"Sector {sector} — no default key worked (custom key)")

        reader.MFRC522_StopCrypto1()
        print("\nDone. Remove card or hold another one.\n")

finally:
    GPIO.cleanup()
