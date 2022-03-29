from zdppy_password import Base64

if __name__ == '__main__':
    # 编码
    data = Base64.encode("abc123张大鹏")
    print(data)

    # 解码
    print(Base64.decode(data))

    # 编码字符串
    data = Base64.encode_str("abc123张大鹏")
    print(data)

    # 解码字符串
    print(Base64.decode_str(data))

    # 从go复制过来的
    data = "NoA3e0HDMhj7nrwKUx975lUZgjRIA1ZFcEBLeAvgYQ7Nu7toic7xXtg9qmD+wr6soZzb6Gl37H1I5j9OlOTR9igQ+p1pXPOWo47DyDpw3UjiQ6eOAYmyT53lMUGylLZIKHhnbpea5Qpjl+dHrWVYsQ864/asS1ewe9k2hR+BlkBuZSP8p6oiJ+BBOVYckqPFf6PWBjAFGAMridMXglYrKZ2v7+QdwU4mq2YEBVD5XdY70lIEg4XIY8Wb6n5tBB5XkzLsqd22XcBhnEPGLmMC4fuEMyLptH5dMGF/Ogi9YDAP/rKvzdTTpFXPLPh5eeqMMXAS5+AigE1jx1M3w+7IUw=="
    print(Base64.decode(data))
