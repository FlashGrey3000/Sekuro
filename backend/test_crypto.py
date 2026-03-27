from crypto import *

# User A
a_private, a_public = generate_keypair()

# User B
b_private, b_public = generate_keypair()

# Exchange keys
a_peer = load_public_key(b_public)
b_peer = load_public_key(a_public)

# Derive shared secrets
a_secret = derive_shared_secret(a_private, a_peer)
b_secret = derive_shared_secret(b_private, b_peer)

# Derive AES keys
a_key = derive_aes_key(a_secret)
b_key = derive_aes_key(b_secret)

print(a_key == b_key)  # MUST be True

# Encrypt & decrypt
nonce, ciphertext = encrypt_message(a_key, "hello shinobi")

message = decrypt_message(b_key, nonce, ciphertext)

print(message)

# ===== Expected Output ====== #
# True
# hello shinobi
# ============================ #

# if not the above output then something must be terribly wrong...