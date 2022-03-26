import os

from Crypto import Random
from Crypto.PublicKey import RSA
from zdppy_log import Log


class Rsa:
    def __init__(
            self,
            key_length: int = 1024,
            log_file_path: str = "logs/zdppy/zdppy_password.log",
            debug: bool = True,
    ):
        """
        初始化Rsa加密对象
        :param key_length: 生成key的长度，长度越长越安全，但是速度也越慢。必须大于或等于1024。
        """
        random_generator = Random.new().read
        self.rsa = RSA.generate(key_length, random_generator)
        self.log = Log(log_file_path=log_file_path, debug=debug)

    def generate_private_key(
            self,
            private_key_path: str = None,
            is_to_str: bool = True,
    ):
        """
        生成RSA私钥
        :param is_to_str: 是否转换为字符串
        :param private_key_path: 私钥文件保存的路径
        :return: 私钥
        """
        # 如果已存在，读取返回
        if private_key_path is not None and os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                result = f.read()
                if is_to_str:
                    result = result.decode()
                return result

        # 生成私钥
        result = self.rsa.exportKey()

        # 保存
        if private_key_path is not None and isinstance(private_key_path, str):
            with open(private_key_path, "wb") as f:
                f.write(result)

        # 转换为字符串
        if is_to_str:
            result = result.decode('utf-8')

        # 返回结果
        return result

    def generate_public_key(
            self,
            public_key_path: str = None,
            is_to_str: bool = True,
    ):
        """
        生成RSA公钥
        :param is_to_str: 是否转换为字符串
        :param public_key_path: 公钥文件保存的路径
        :return: 公钥
        """
        # 如果已存在，读取返回
        if public_key_path is not None and os.path.exists(public_key_path):
            with open(public_key_path, "rb") as f:
                result = f.read()
                if is_to_str:
                    result = result.decode()
                return result

        # 生成公钥
        result = self.rsa.publickey().exportKey()

        # 保存
        if public_key_path is not None and isinstance(public_key_path, str):
            with open(public_key_path, "wb") as f:
                f.write(result)

        # 转换为字符串
        if is_to_str:
            result = result.decode('utf-8')

        # 返回结果
        return result
