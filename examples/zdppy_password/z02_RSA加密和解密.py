from zdppy_password import Rsa, Base64
import json

rsa = Rsa()


def default_demo():
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


def sha1_demo():
    data = {"username": "张大鹏", "age": 22}
    data = json.dumps(data)
    print(data)

    # 加密
    secret = rsa.encrypt_sha1_str(data)
    print("加密：", secret)

    # 解密
    result = rsa.decrypt_sha1_str(secret)
    print("===", result)
    print("===", json.loads(result))

    # 从go复制过来的
    data = "j+Lc1OtOu+rF9d+cKvU7IUmQ/WNTQk20t5mEABcT2liWPic2KIuF8jbQrstBdvh7zmj1KIYf5z6PD9CNCfLPnthD6k1+tLVBWPkCj3x6LVrURInJRJTHh6QrcvxM1ZmT563/D0okw9O0cr8Qc3nMDT2/dUTEpzShT3dPG76ztoX4nSd4MMEbBIOTT3G7deglwMZNDVMfUmgLz2WTa2lijfTrL7rpGcD0ofeqjUXmYPo6OV0dQV6A1myJqcSHTGNcmwvaZhGVxrKW87nB5ZJnZcYkLfpm+1YFr93iR+Qj1ygjhTqnX5pwxyoNg090/1omvXYv8jSq2mhArAVncRl7KA=="
    print(rsa.decrypt_sha1(Base64.decode(data)).decode("utf-8"))


def sign_demo():
    """
    测试签名和校验
    :return:
    """
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


if __name__ == '__main__':
    # default_demo()
    # sha1_demo()
    sign_demo()
