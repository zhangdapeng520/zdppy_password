from zdppy_password.rsa import Rsa

rsa = Rsa()

# 生成私钥
print(rsa.generate_private_key())

# 生成公钥
print(rsa.generate_public_key())

# 保存私钥
print(rsa.generate_private_key("private_key.pem"))

# 保存公钥
print(rsa.generate_public_key("public_key.pem"))
