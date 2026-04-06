import secrets
# Generate 32 random bytes (256 bits) and convert to hex
secret_code = secrets.token_hex(256)
print(secret_code)
