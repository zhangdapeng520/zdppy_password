from .libs import rsa


class Rsa:
    def __init__(self):
        """
        初始化Rsa加密对象
        """
        self.private_key = None  # 私钥
        self.public_key = None  # 公钥
        self.public_key, self.private_key = rsa.newkeys(2048)

    def encrypt(self, data, public_key):
        """
        加密
        :param data 要加密的内容
        :param public_key 公钥
        :return:
        """
        # 编码
        temp = data.encode("utf8")

        # 加密
        crypto = rsa.encrypt(temp, public_key)

        # 返回加密结果
        return crypto

    def decrypt(self, data, private_key):
        """
        解密
        :param data: 加密的数据
        :param private_key: 私钥
        :return:
        """
        # 将字符串类型转换为字节类型
        if isinstance(data, str):
            data = data.encode("utf8")

        temp = rsa.decrypt(data, private_key)
        result = temp.decode("utf8")
        return result
