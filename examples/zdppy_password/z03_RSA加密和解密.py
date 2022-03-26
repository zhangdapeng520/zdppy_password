from zdppy_password.rsa import Rsa
import json

rsa = Rsa()

data = {"username": "张大鹏", "age": 22}
data = json.dumps(data)
print(data)

# 加密
secret = rsa.encrypt(data, "public_key.pem")
print(secret)

# 解密
print(rsa.decrypt(secret))
print(json.loads(rsa.decrypt(secret)))
