import base64
import traceback

from Crypto.Cipher import AES
from .type_tool import TypeTool
from .b64 import Base64


def pkcs7padding(data):
    bs = AES.block_size
    padding = bs - len(data) % bs
    padding_text = chr(padding) * padding
    return data + padding_text.encode()


def pkcs7unpadding(data):
    lengt = len(data)
    unpadding = data[lengt - 1] if type(data[lengt - 1]) is int else ord(data[lengt - 1])
    return data[0:lengt - unpadding]


class Aes:
    """
    AES加密
    """

    def __init__(self, key: str = "_ZhangDapeng520%"):
        self.key = key.encode()

    def encrypt(self, data):
        """
        AES 加密， 加密模式ECB，填充：pkcs7padding，密钥长度：256
        :param data:
        :return:
        """
        data = pkcs7padding(data)
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return base64.b64encode(encrypted)

    def decrypt(self, data):
        """
        AES解密
        :param data: 要解密的数据
        :return: 解密后的数据
        """
        data = base64.b64decode(data)
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted = cipher.decrypt(data)
        decrypted = pkcs7unpadding(decrypted)
        return decrypted.decode()

    @classmethod
    @TypeTool.type_assert
    def encrypt_gcm(cls,
                    cdata: [str, bytes, bytearray],
                    key: [str, bytes, bytearray]) -> [tuple]:
        """
        AES加密
        :param cdata: 要加密的数据
        :param key: 加密的key
        :return:
        """
        error_return = (bytes(), bytes(), bytes())
        try:
            # 将参数转换为字节数组
            cdata = TypeTool.type_sbb_2_bytes(cdata)
            key = TypeTool.type_sbb_2_bytes(key)

            # 校验参数的长度
            if len(key) != 16:
                return error_return

            # 创建cipher对象
            aescipher = AES.new(key, AES.MODE_GCM)

            # 加密
            edata, tag = aescipher.encrypt_and_digest(cdata)

            # 获取nonce
            nonce = aescipher.nonce

            # 返回加密结果
            return edata, nonce, tag
        except Exception as e:
            print(e)
            traceback.print_exc()

            # 返回错误结果
            return error_return

    @classmethod
    def encrypt_gcm_str(cls,
                        cdata: str,
                        key: str) -> (str, str, str):
        """
        AES加密字符串
        :param cdata: 要加密的数据
        :param key: 加密的key
        :return: 加密后的数据base6编码字符串
        """

        # 加密
        edata, nonce, tag = cls.encrypt_gcm(cdata.encode(), key.encode())

        # 转换为base64编码
        edata_b64 = Base64.encode_str(edata)
        nonce_b64 = Base64.encode_str(nonce)
        tag_b64 = Base64.encode_str(tag)

        # 返回base64编码
        return edata_b64, nonce_b64, tag_b64

    @classmethod
    @TypeTool.type_assert
    def decrypt_gcm(cls,
                    edata: [str, bytes, bytearray],
                    key: [str, bytes, bytearray],
                    nonce: [str, bytes, bytearray],
                    tag: [str, bytes, bytearray]) -> [bytes]:
        """
        AES解密
        :param edata: 要解密的数据
        :param key: 解密的key
        :param nonce: 解密的nonce
        :param tag: 解密的标签
        :return: 解密后的数据
        """
        error_return = bytes()
        try:
            # 将参数都转换为字节数组
            edata = TypeTool.type_sbb_2_bytes(edata)
            key = TypeTool.type_sbb_2_bytes(key)
            nonce = TypeTool.type_sbb_2_bytes(nonce)
            tag = TypeTool.type_sbb_2_bytes(tag)

            # 判断参数的长度
            if (len(key) != 16) or (len(nonce) != 16) or (len(tag) != 16):
                return error_return

            # 创建cipher
            aescipher = AES.new(key, AES.MODE_GCM, nonce)

            # 数据解密并校验
            cdata = aescipher.decrypt_and_verify(edata, tag)

            # 返回解密后的数据
            return cdata
        except Exception as e:
            print(e)
            traceback.print_exc()
            return error_return

    @classmethod
    def decrypt_gcm_str(cls,
                        edata: str,
                        key: str,
                        nonce: str,
                        tag: str) -> str:
        """
        解密字符串
        :param edata: 要解密的数据
        :param key: 解密的key
        :param nonce: 解密的nonce
        :param tag: 解密的tag
        :return: 解密后的字符串
        """
        # 将参数转换为字节数组
        edata_bytes = Base64.decode(edata)
        key_bytes = key.encode()
        nonce_bytes = Base64.decode(nonce)
        tag_bytes = Base64.decode(tag)

        # 解密
        result_bytes = cls.decrypt_gcm(edata_bytes, key_bytes, nonce_bytes, tag_bytes)

        # 将解密结果解码
        return result_bytes.decode('utf-8')
