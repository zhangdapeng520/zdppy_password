import os
import traceback
import coincurve
import ecies
from coincurve.utils import sha256
from .type_tool import TypeTool
from .b64 import Base64


class Ecc:
    @classmethod
    @TypeTool.type_assert
    def generate_key_pair(cls) -> [tuple]:
        """
        生成公钥和私钥
        :return:
        """
        # 生成私钥
        private_key = coincurve.PrivateKey()

        # 将公钥和私钥base64编码
        b64_private_key = Base64.encode(private_key.secret)
        b64_public_key = Base64.encode(private_key.public_key.format())

        # 返回公钥和私钥
        return b64_private_key, b64_public_key

    @classmethod
    @TypeTool.type_assert
    def encrypt(cls,
                data: [str, bytes, bytearray],
                public_key: [str, bytes, bytearray]) -> [bytes]:
        """
        ecc加密
        :param data: 要加密的数据
        :param public_key: 公钥
        :return: 加密后的数据
        """
        error_return = bytes()
        try:
            # 将数据转换为字节数组
            data = TypeTool.type_sbb_2_bytes(data)
            public_key = TypeTool.type_sbb_2_bytes(public_key)

            # 进行加密
            return ecies.encrypt(Base64.decode(public_key), data)
        except:
            traceback.print_exc()
            return error_return

    @classmethod
    @TypeTool.type_assert
    def decrypt(cls,
                data: [str, bytes, bytearray],
                private_key: [str, bytes, bytearray]) -> bytes:
        """
        ECC解密
        :param data: 要解密的数据
        :param private_key: 私钥
        :return:
        """
        error_return = bytes()
        try:
            # 将参数转换为字节数组
            data = TypeTool.type_sbb_2_bytes(data)
            private_key = TypeTool.type_sbb_2_bytes(private_key)

            # 进行解密
            return ecies.decrypt(Base64.decode(private_key), data)
        except:
            traceback.print_exc()
            return error_return

    @classmethod
    @TypeTool.type_assert
    def sign(cls,
             data: [str, bytes, bytearray],
             private_key: [str, bytes, bytearray],
             hasher=sha256) -> [bytes]:
        """
        生成签名
        :param data: 要签名的数据
        :param private_key: 私钥
        :param hasher: hash算法
        :return:
        """
        signature = bytes()
        try:
            data = TypeTool.type_sbb_2_bytes(data)
            private_key = TypeTool.type_sbb_2_bytes(private_key)
            private_key_obj = coincurve.PrivateKey(Base64.decode(private_key))
            signature = private_key_obj.sign(data, hasher=hasher)
        except:
            traceback.print_exc()
        return Base64.encode(signature)

    @classmethod
    @TypeTool.type_assert
    def verify(cls,
               data: [str, bytes, bytearray],
               signature: [str, bytes, bytearray],
               public_key: [str, bytes, bytearray],
               hasher=sha256) -> [bool]:
        """
        验证签名
        :param data: 要验证签名的数据
        :param signature: 签名
        :param public_key: 公钥
        :param hasher: hash算法
        :return: 验证结果
        """
        result = False
        try:
            data = TypeTool.type_sbb_2_bytes(data)
            signature = TypeTool.type_sbb_2_bytes(signature)
            public_key = TypeTool.type_sbb_2_bytes(public_key)
            public_key_obj = coincurve.PublicKey(Base64.decode(public_key))
            return public_key_obj.verify(Base64.decode(signature), data, hasher=hasher)
        except:
            traceback.print_exc()
            return result
