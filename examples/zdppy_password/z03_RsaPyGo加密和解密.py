from zdppy_password import RsaPyGo
import json

rsa = RsaPyGo()

data = {"username": "张大鹏", "age": 22}
data = json.dumps(data)
print(data)

# 加密
secret = rsa.encrypt(data, "public.pem")

# 解密
print(json.loads(rsa.decrypt(secret, "private.pem")))

# 从go复制过来的
data = "NoA3e0HDMhj7nrwKUx975lUZgjRIA1ZFcEBLeAvgYQ7Nu7toic7xXtg9qmD+wr6soZzb6Gl37H1I5j9OlOTR9igQ+p1pXPOWo47DyDpw3UjiQ6eOAYmyT53lMUGylLZIKHhnbpea5Qpjl+dHrWVYsQ864/asS1ewe9k2hR+BlkBuZSP8p6oiJ+BBOVYckqPFf6PWBjAFGAMridMXglYrKZ2v7+QdwU4mq2YEBVD5XdY70lIEg4XIY8Wb6n5tBB5XkzLsqd22XcBhnEPGLmMC4fuEMyLptH5dMGF/Ogi9YDAP/rKvzdTTpFXPLPh5eeqMMXAS5+AigE1jx1M3w+7IUw=="
print(rsa.decrypt(data, "private.pem"))
