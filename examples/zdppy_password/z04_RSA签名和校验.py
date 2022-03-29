from zdppy_password import Rsa
import json

rsa = Rsa()

data = {"username": "张大鹏", "age": 22}
data = json.dumps(data)
print(data)

# 签名
signer = rsa.sign(data)
print(signer)

# 校验
print(rsa.verify(data, signer))

# 修改再校验
data = {"username": "张大鹏", "age": 23}
data = json.dumps(data)
print(rsa.verify(data, signer))
