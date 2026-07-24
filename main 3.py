#!/usr/bin/env python3
"""
main3.py
Vigenère + AES-256 menu program.
Uses aes.py from the same folder.
"""

from __future__ import annotations

import os
import base64
import hashlib
import aes

# ----------------------------
# Files for keys
# ----------------------------
VIG_KEY_FILE = "key.txt"
AES_KEY_FILE = "aes_key.bin"
AES_SALT_FILE = "aes_salt.bin"

# ----------------------------
# Vigenère key helpers
# ----------------------------

def normalize_vigenere_key(key: str) -> str:
    cleaned = "".join(ch for ch in key if ch.isalpha()).upper()
    return cleaned or "DEFAULTKEY"

try:
    with open(VIG_KEY_FILE, "r", encoding="utf-8") as f:
        encryption_key = normalize_vigenere_key(f.read().strip())
except FileNotFoundError:
    encryption_key = "DEFAULTKEY"

# ----------------------------
# AES key loading
# ----------------------------

def load_aes_material():
    loaded_key = None
    loaded_salt = None

    if os.path.exists(AES_KEY_FILE) and os.path.exists(AES_SALT_FILE):
        try:
            with open(AES_KEY_FILE, "rb") as f:
                loaded_key = f.read()

            with open(AES_SALT_FILE, "rb") as f:
                loaded_salt = f.read()

            if len(loaded_key) != 32:
                print("Saved AES key is invalid. Press K to create a fresh 32-byte key.")
                loaded_key = None
                loaded_salt = None
            elif len(loaded_salt) != 16:
                print("Saved AES salt is invalid. Press K to create a fresh one.")
                loaded_key = None
                loaded_salt = None

        except Exception as e:
            print(f"Could not load AES key files: {e}")
            loaded_key = None
            loaded_salt = None

    return loaded_key, loaded_salt

aes_key, aes_salt = load_aes_material()

# ----------------------------
# Vigenère functions
# ----------------------------

def generate_key(text, key):
    key = normalize_vigenere_key(key)
    if not key:
        key = "DEFAULTKEY"

    key_chars = list(key)
    for i in range(len(text) - len(key_chars)):
        key_chars.append(key_chars[i % len(key_chars)])
    return "".join(key_chars)

def encrypt_vigenere(text):
    result = ""
    key = generate_key(text, encryption_key)

    for i, c in enumerate(text):
        if c.isalpha():
            shift = ord(key[i].upper()) - ord("A")
            x = (ord(c.upper()) + shift - ord("A")) % 26 + ord("A")
            result += chr(x) if c.isupper() else chr(x).lower()
        else:
            result += c

    return result

def decrypt_vigenere(text):
    result = ""
    key = generate_key(text, encryption_key)

    for i, c in enumerate(text):
        if c.isalpha():
            shift = ord(key[i].upper()) - ord("A")
            x = (ord(c.upper()) - shift - ord("A")) % 26 + ord("A")
            result += chr(x) if c.isupper() else chr(x).lower()
        else:
            result += c

    return result

# ----------------------------
# AES-256 helpers
# ----------------------------

def derive_aes_key(phrase, salt):
    return hashlib.pbkdf2_hmac("sha256", phrase.encode("utf-8"), salt, 200_000, 32)

def fix_base64_padding(data):
    data = data.strip()
    missing = len(data) % 4
    if missing:
        data += "=" * (4 - missing)
    return data

def aes_encrypt(text):
    global aes_key

    if not aes_key or len(aes_key) != 32:
        return "AES key not set or invalid"

    try:
        iv = os.urandom(16)
        cipher = aes.AES(aes_key)
        encrypted = cipher.encrypt_cbc(text.encode("utf-8"), iv)
        return base64.b64encode(iv + encrypted).decode("ascii")
    except Exception as e:
        return f"AES encrypt failed: {e}"

def aes_decrypt(token):
    global aes_key

    if not aes_key or len(aes_key) != 32:
        return "AES key not set or invalid"

    try:
        token = fix_base64_padding(token)
        raw = base64.b64decode(token)

        if len(raw) < 32:
            return "AES decrypt failed: data too short"

        iv = raw[:16]
        data = raw[16:]

        if len(data) % 16 != 0:
            return "AES decrypt failed: corrupted ciphertext length"

        cipher = aes.AES(aes_key)
        decrypted = cipher.decrypt_cbc(data, iv)
        return decrypted.decode("utf-8")
    except Exception as e:
        return f"AES decrypt failed: {e}"

# ----------------------------
# Auto decrypt
# ----------------------------

def auto_decrypt(text):
    results = {}

    try:
        results["Vigenère"] = decrypt_vigenere(text)
    except Exception:
        results["Vigenère"] = "Failed"

    try:
        results["AES-256"] = aes_decrypt(text)
    except Exception:
        results["AES-256"] = "Failed"

    try:
        temp = aes_decrypt(text)
        if temp.startswith("AES decrypt failed") or temp == "AES key not set or invalid":
            raise ValueError("AES step failed")
        results["Double (AES → Vigenère)"] = decrypt_vigenere(temp)
    except Exception:
        results["Double (AES → Vigenère)"] = "Failed"

    return results

# ----------------------------
# Main
# ----------------------------

def main():
    global encryption_key, aes_key, aes_salt

    while True:
        print(
            """
(E) Encrypt (Vigenère)
(D) Decrypt (Vigenère)
(A) AES-256 Encrypt
(B) AES-256 Decrypt
(X) Double Encrypt (Vigenère → AES)
(Y) Double Decrypt (AES → Vigenère)
(U) Auto Decrypt (try ALL)
(K) Change AES key
(C) Change Vigenère key
(Q) Quit
"""
        )

        choice = input("Choice: ").strip().upper()

        if choice == "Q":
            break

        if choice == "C":
            new_key = input("New Vigenère key: ").strip()
            new_key = normalize_vigenere_key(new_key)
            if new_key == "DEFAULTKEY":
                print("Vigenère key cannot be empty.")
                continue

            encryption_key = new_key
            with open(VIG_KEY_FILE, "w", encoding="utf-8") as f:
                f.write(encryption_key)
            print("Vigenère key saved.")
            continue

        if choice == "K":
            phrase = input("Enter AES passphrase: ").strip()
            if not phrase:
                print("AES passphrase cannot be empty.")
                continue

            aes_salt = os.urandom(16)
            aes_key = derive_aes_key(phrase, aes_salt)

            if len(aes_key) != 32:
                print("AES key generation failed.")
                aes_key = None
                aes_salt = None
                continue

            with open(AES_KEY_FILE, "wb") as f:
                f.write(aes_key)

            with open(AES_SALT_FILE, "wb") as f:
                f.write(aes_salt)

            print("AES-256 key saved.")
            continue

        text = input("Enter text: ")

        if choice == "E":
            print(encrypt_vigenere(text))

        elif choice == "D":
            print(decrypt_vigenere(text))

        elif choice == "A":
            print(aes_encrypt(text))

        elif choice == "B":
            print(aes_decrypt(text))

        elif choice == "X":
            print(aes_encrypt(encrypt_vigenere(text)))

        elif choice == "Y":
            temp = aes_decrypt(text)
            if temp.startswith("AES decrypt failed") or temp == "AES key not set or invalid":
                print(temp)
            else:
                print(decrypt_vigenere(temp))

        elif choice == "U":
            print("\n--- Auto Decrypt Results ---")
            for k, v in auto_decrypt(text).items():
                print(f"{k}: {v}")

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()