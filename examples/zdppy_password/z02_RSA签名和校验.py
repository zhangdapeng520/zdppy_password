from zdppy_password.rsa import Rsa

rsa = Rsa()
data = "hello Bob!"
print(rsa.private_key, rsa.public_key)

# 签名
signature = rsa.signature(data, rsa.private_key)
print(signature)

# 校验
print(rsa.verify(data, signature, rsa.public_key))

# 修改
data = "hello Bob1!"

# 再校验
print(rsa.verify(data, signature, rsa.public_key))
