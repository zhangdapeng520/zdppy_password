# zdppy_password
Python密码工具

项目地址：https://github.com/zhangdapeng520/zdppy_password

安装方式
```shell
pip install zdppy_password
```

## 版本历史
- 2022年3月29日 版本0.1.0 兼容Python和Go的AES RSA加密解密算法

## 常用命令
生成私钥
```shell
openssl genrsa -out private.pem 1024
```

生成公钥
```shell
openssl rsa -in private.pem -pubout -out public.pem
```

## 使用案例
### 案例1：AES加密和解密
```python
from zdppy_password.aes import Aes

aes = Aes()
res = aes.encrypt(b'{"cmd": 3000, "msg": "ok"}').decode(encoding='utf-8')
print(res)
print(aes.decrypt(res))

# 从go复制过来的
print(aes.decrypt("0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="))
```

## 案例2：RSA加密和解密
```python
from zdppy_password.rsa import Rsa
import json

rsa = Rsa()

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
```