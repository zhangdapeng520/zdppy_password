from zdppy_password.hash import Hash

if __name__ == '__main__':
    # 测试hash
    print(Hash.hash("1"))
    print(Hash.hash("123"))

    # 测试md5算法
    print(Hash.md5("1"))
    print(Hash.md5("123".encode()))
