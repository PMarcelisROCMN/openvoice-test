common_keys = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],  # Default everywhere
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # All zeros
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],  # NXP MAD default Key A
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
    [0xA3, 0x96, 0xEF, 0xA4, 0xE2, 0x4F],  # Some backdoor variants
    [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD],
    [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F],  # Another frequent one
    # You can add more from full dictionaries (see note below)
]

import time
from mfrc522 import MFRC522

reader = MFRC522()

print("Place your MIFARE card on the RC522...")

while True:
    (status, TagType) = reader.Request(reader.PICC_REQIDL)
    if status != reader.MI_OK:
        time.sleep(0.1)
        continue

    (status, uid) = reader.Anticoll()
    if status != reader.MI_OK:
        continue

    print(f"\nCard detected! UID: {[hex(x) for x in uid]}")
    reader.SelectTag(uid)

    # Try to find key for every sector (1K card = 16 sectors)
    for sector in range(16):
        trailer_block = sector * 4 + 3  # Sector trailer always holds the keys
        key_found = False

        for key in common_keys:
            # Try Key A first (most common)
            status = reader.MFRC522_Auth(reader.PICC_AUTHENT1A, trailer_block, key, uid)
            if status == reader.MI_OK:
                print(f"✅ Sector {sector} → Key A found: {[hex(b) for b in key]}")
                key_found = True
                # Optional: read the data blocks here
                break

            # Then try Key B
            status = reader.MFRC522_Auth(reader.PICC_AUTHENT1B, trailer_block, key, uid)
            if status == reader.MI_OK:
                print(f"✅ Sector {sector} → Key B found: {[hex(b) for b in key]}")
                key_found = True
                break

        if not key_found:
            print(f"❌ No common key found for sector {sector}")

    reader.StopCrypto1()  # Clean up
    print("Done scanning. Remove card or press Ctrl+C to exit.\n")
    time.sleep(2)  # Avoid re-triggering instantly
