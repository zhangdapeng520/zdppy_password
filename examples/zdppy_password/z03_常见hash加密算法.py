from zdppy_password import Hash

if __name__ == '__main__':
    # 测试hash
    print(Hash.hash("1"))
    print(Hash.hash("123"))

    # 测试md5算法
    print(Hash.md5("1"))
    print(Hash.md5("123".encode()))

    # 不加盐
    print(Hash.sha1("abc"))
    print(Hash.sha1_verify("123456", Hash.sha1("123456")))

    # 加盐
    print(Hash.sha1("123456", "salt"))
    print(Hash.sha1_verify("123456", Hash.sha1("123456", "salt"), "salt"))

    # 不加盐
    print(Hash.sha256("abc"))
    print(Hash.sha256_verify("123456", Hash.sha256("123456")))

    # 加盐
    print(Hash.sha256("123456", "salt"))
    print(Hash.sha256_verify("123456", Hash.sha256("123456", "salt"), "salt"))

    # 不加盐
    print(Hash.sha512("abc"))
    print(Hash.sha512_verify("123456", Hash.sha512("123456")))

    # 加盐
    print(Hash.sha512("123456", "salt"))
    print(Hash.sha512_verify("123456", Hash.sha512("123456", "salt"), "salt"))
