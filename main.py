import time
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Funkcja do odczytu pliku
def read_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    return file_data

# Funkcja do zapisu pliku
def write_file(file_path, file_data):
    with open(file_path, 'wb') as file:
        file.write(file_data)


# Funkcja do szyfrowania i odszyfrowania pliku w trybie ECB
def encrypt_ecb(key, file_data):
    cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(file_data, DES3.block_size))
    return encrypted_data

def decrypt_ecb(key, encrypted_data):
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
    return decrypted_data


# Funkcja do szyfrowania i odszyfrowania pliku w trybie CBC
def encrypt_cbc(key, iv, file_data):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(file_data, DES3.block_size))
    return encrypted_data

def decrypt_cbc(key, iv, encrypted_data):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
    return decrypted_data


# Funkcja do szyfrowania i odszyfrowania pliku w trybie CFB
def encrypt_cfb(key, file_data):
    cipher = DES3.new(key, DES3.MODE_CFB, segment_size=DES3.block_size * 8)
    encrypted_data = cipher.encrypt(file_data)
    return encrypted_data

def decrypt_cfb(key, encrypted_data):
    cipher = DES3.new(key, DES3.MODE_CFB, segment_size=DES3.block_size * 8)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data


# Funkcja do szyfrowania i odszyfrowania pliku w trybie OFB
def encrypt_ofb(key, file_data):
    cipher = DES3.new(key, DES3.MODE_OFB)
    encrypted_data = cipher.encrypt(file_data)
    return encrypted_data

def decrypt_ofb(key, encrypted_data):
    cipher = DES3.new(key, DES3.MODE_OFB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data


# Funkcja do szyfrowania i odszyfrowania pliku w trybie CTR
def encrypt_ctr(key, iv, file_data):
  cipher = DES3.new(key, DES3.MODE_CTR, nonce=iv)
  encrypted_data = cipher.encrypt(file_data)
  return encrypted_data

def decrypt_ctr(key, iv, encrypted_data):
  cipher = DES3.new(key, DES3.MODE_CTR, nonce=iv)
  decrypted_data = cipher.decrypt(encrypted_data)
  return decrypted_data


def main():
  input_file_path = "rocky.iso"
  # Ścieżka do pliku wyjściowego
  output_file_path = "encrypted_file.bin"
  # Klucz szyfrowania
  key = get_random_bytes(24)

  # Wektor inicjujący dla trybu CTR musi dwa razy mniejszy
  iv_CTR = get_random_bytes(8//2)
  iv = get_random_bytes(8)

  # Odczyt pliku
  file_data = read_file(input_file_path)

  # =========== Szyfrowanie i deszyfrowanie w trybie ECB ===========
  start_time = time.time()
  encrypted_data = encrypt_ecb(key, file_data)
  decryption_time = time.time() - start_time
  print("ECB encryption time:", decryption_time)
  start_time = time.time()

  decrypted_data = decrypt_ecb(key, encrypted_data)
  decryption_time = time.time() - start_time
  print("ECB decryption time:", decryption_time)
  write_file(output_file_path, encrypted_data)

  # =========== Szyfrowanie i deszyfrowanie w trybie CBC ===========
  start_time = time.time()
  encrypted_data = encrypt_cbc(key, iv, file_data)
  decryption_time = time.time() - start_time
  print("CBC encryption time:", decryption_time)
  start_time = time.time()

  decrypted_data = decrypt_cbc(key, iv, encrypted_data)
  decryption_time = time.time() - start_time
  print("CBC decryption time:", decryption_time)
  write_file(output_file_path, encrypted_data)

  # =========== Szyfrowanie i deszyfrowanie w trybie CFB ===========
  start_time = time.time()
  encrypted_data = encrypt_cfb(key, file_data)
  decryption_time = time.time() - start_time
  print("CFB encryption time:", decryption_time)
  start_time = time.time()

  decrypted_data = decrypt_cfb(key, encrypted_data)
  decryption_time = time.time() - start_time
  print("CFB decryption time:", decryption_time)
  write_file(output_file_path, encrypted_data)

  # =========== Szyfrowanie i deszyfrowanie w trybie OFB ===========
  start_time = time.time()
  encrypted_data = encrypt_ofb(key, file_data)
  decryption_time = time.time() - start_time
  print("OFB encryption time:", decryption_time)
  start_time = time.time()
  
  decrypted_data = decrypt_ofb(key, encrypted_data)
  decryption_time = time.time() - start_time
  print("OFB decryption time:", decryption_time)
  write_file(output_file_path, encrypted_data)

  # =========== Szyfrowanie i deszyfrowanie w trybie CTR ===========
  start_time = time.time()
  encrypted_data = encrypt_ctr(key, iv_CTR, file_data)
  decryption_time = time.time() - start_time
  print("CTR encryption time:", decryption_time)
  start_time = time.time() 

  decrypted_data = decrypt_ctr(key, iv_CTR, encrypted_data)
  decryption_time = time.time() - start_time
  print("CTR decryption time:", decryption_time)
  write_file(output_file_path, encrypted_data)

main()