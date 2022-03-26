from zdppy_password.rsa import Rsa

rsa = Rsa()
data = "hello Bob!"
print(rsa.private_key, rsa.public_key)

# 加密
temp = rsa.encrypt(data, rsa.public_key)
print(temp)

# 解密
print(rsa.decrypt(temp, rsa.private_key))
