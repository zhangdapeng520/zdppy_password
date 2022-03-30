from zdppy_password import Ecc

# 创建私钥
ecc = Ecc()


def default_demo():
    data = 'abc 123 张大鹏'

    # 生成公钥和四啊哟
    private_key, public_key = ecc.generate_key_pair()
    print("私钥：", private_key)
    print("公钥：", public_key)

    encrypted_data = ecc.encrypt(data.encode(), public_key)
    print("加密：", encrypted_data)

    # 解密内容
    decrypted_data = ecc.decrypt(encrypted_data, private_key)
    print("解密：", decrypted_data.decode())


def sign_demo():
    data = 'abc 123 张大鹏'

    # 生成公钥和四啊哟
    private_key, public_key = ecc.generate_key_pair()

    # 签名
    signer = ecc.sign(data, private_key)
    print("签名：", signer)

    # 验证签名
    result = ecc.verify(data, signer, public_key)
    print("验证签名：", result)

    # 修改再验证
    data = 'abc 123 张大鹏11'
    result = ecc.verify(data, signer, public_key)
    print("验证签名：", result)


if __name__ == '__main__':
    default_demo()
    # sign_demo()
