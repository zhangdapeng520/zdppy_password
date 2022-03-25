from zdppy_password.rsa import Rsa

rsa = Rsa()
print(rsa.generate_private_key())
print(rsa.generate_public_key())
print(rsa.save_secret_key())
print(rsa.save_public_key())
