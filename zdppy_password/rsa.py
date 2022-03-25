from .libs.Crypto import Random
from .libs.Crypto.PublicKey import RSA


class Rsa:
    def __init__(self):
        """
        初始化Rsa加密对象
        """
        self.private_key = None  # 私钥
        self.public_key = None  # 公钥
        self.random_generator = Random.new().read  # 随机数据生成器
        self.rsa = RSA.generate(2048, self.random_generator)  # 生成rsa对象

    def generate_private_key(self, is_to_str: bool = True):
        """
        生成私钥
        :param is_to_str 是否转换为字符串
        :return:
        """
        # 生成私钥
        private_key = self.rsa.exportKey()
        self.private_key = private_key

        # 转换为字符串
        if is_to_str:
            private_key = private_key.decode('utf-8')

        # 返回私钥
        return private_key

    def generate_public_key(self, is_to_str: bool = True):
        """
        生成公钥
        :param is_to_str 是否转换为字符串
        :return:
        """
        # 生成公钥
        public_key = self.rsa.publickey().exportKey()
        self.public_key = public_key

        # 转换为字符串
        if is_to_str:
            public_key = public_key.decode('utf-8')

        # 返回公钥
        return public_key

    def save_secret_key(self, path: str = "rsa_private_key.pem"):
        """
        保存私钥
        :param path 私钥文件地址
        :return:
        """

        # 写入私钥
        with open(path, 'wb') as f:
            f.write(self.private_key)

    def save_public_key(self, path: str = "rsa_public_key.pem"):
        """
        保存公钥
        :param path 公钥文件地址
        :return:
        """

        # 写入私钥
        with open(path, 'wb') as f:
            f.write(self.public_key)
