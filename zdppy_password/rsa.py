import os.path

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
import traceback
from .type_tool import TypeTool
from .b64 import Base64


class Rsa:
    @classmethod
    @TypeTool.type_assert
    def sign(cls,
             sdata: [str, bytes, bytearray],
             private_key: [str, bytes, bytearray] = None) -> [bytes]:
        """
        对数据进行签名
        :param sdata: 要签名的数据
        :param private_key: 签名私钥，使用该私钥进行数据签名
        :return:
        """
        # 默认使用private.pem作为私钥
        if private_key is None:
            if os.path.exists("private.pem"):
                with open("private.pem", "rb") as f:
                    private_key = f.read()

        # 签名
        ssign = bytes()

        try:
            # 将数据转换为字节数组
            sdata = TypeTool.type_sbb_2_bytes(sdata)

            # 将公钥转换为字节数组
            rsa_key = TypeTool.type_sbb_2_bytes(private_key)

            # 创建hash对象
            rhash = SHA384.new()

            # 对要加密的数据进行hash加密
            rhash.update(sdata)

            # 如果没有加密成功，返回空的签名
            if not rhash:
                return ssign

            # 导入私钥
            pkey = RSA.import_key(rsa_key)

            # 创建rsa的cipher
            rsa_cipher = pkcs1_15.new(pkey)

            # 对hash加密后的数据进行签名，并转换为base64编码，然后返回字节数组
            ssign = Base64.encode(rsa_cipher.sign(rhash))
        except Exception as e:
            print(e)
            traceback.print_exc()

        # 返回签名
        return ssign

    @classmethod
    @TypeTool.type_assert
    def verify(cls,
               sdata: [str, bytes, bytearray],
               ssign: [str, bytes, bytearray],
               public_key: [str, bytes, bytearray] = None) -> bool:
        """
        对数据使用签名进行校验
        :param sdata: 要校验的数据
        :param ssign: 签名
        :param public_key: rsa的公钥
        :return: 返回校验结果
        """
        # 默认使用private.pem作为私钥
        if public_key is None:
            if os.path.exists("public.pem"):
                with open("public.pem", "rb") as f:
                    public_key = f.read()

        # 校验结果
        result = False
        try:
            # 将要验证的数据转换为字节数组
            sdata = TypeTool.type_sbb_2_bytes(sdata)

            # 将前面转换为字节数组
            ssign = TypeTool.type_sbb_2_bytes(ssign)

            # 激昂公钥转换为字节数组
            rsa_key = TypeTool.type_sbb_2_bytes(public_key)

            # 创建hash加密对象
            rhash = SHA384.new()

            # 对要验证签名的数据进行hash加密
            rhash.update(sdata)

            # 加密失败则返回验证失败
            if not rhash:
                return result

            # 导入公钥
            pkey = RSA.import_key(rsa_key)

            # 使用公钥创建cipher
            rsa_cipher = pkcs1_15.new(pkey)

            # 使用cipher校验签名
            rsa_cipher.verify(rhash, Base64.decode(ssign))

            # 没有报错则验证签名成功
            result = True
        except Exception as e:
            print(e)
            traceback.print_exc()

            # 报错了则验证失败
            result = False

        # 返回验证结果
        return result

    @classmethod
    @TypeTool.type_assert
    def encrypt(cls,
                cdata: [str, bytes, bytearray],
                public_key: [str, bytes, bytearray] = None) -> bytes:
        """
        使用公钥进行RSA加密
        :param cdata: 要加密的数据
        :param public_key: 公钥
        :return: 加密后的数据
        """
        # 默认使用public.pem作为公钥
        if public_key is None:
            if os.path.exists("public.pem"):
                with open("public.pem", "rb") as f:
                    public_key = f.read()

        error_return = bytes()
        try:
            # 将数据转换为字节数组
            cdata = TypeTool.type_sbb_2_bytes(cdata)

            # 将公钥转换为字节数组
            rsa_key = TypeTool.type_sbb_2_bytes(public_key)

            # 导入公钥
            pkey = RSA.import_key(rsa_key)

            # 创建cipher
            rsa_cipher = PKCS1_OAEP.new(pkey)

            # 正确的返回
            right_return = bytearray()
            tlen = len(cdata)
            sindex = 0

            # 分块加密数据
            while sindex < tlen:
                if tlen - sindex > 214:
                    eindex = sindex + 214
                else:
                    eindex = tlen
                right_return.extend(rsa_cipher.encrypt(cdata[sindex:eindex]))
                sindex = eindex

            # 返回字节数组
            return bytes(right_return)
        except Exception as e:
            print(e)
            traceback.print_exc()

            # 错误返回空字节数组
            return error_return

    @classmethod
    def encrypt_str(cls,
                    data: str,
                    public_key_path: str = "public.pem") -> str:
        # public.pem作为公钥
        public_key = None
        if os.path.exists(public_key_path):
            with open("public.pem", "rb") as f:
                public_key = f.read()
        else:
            return ""  # 无法加密，返回空字符串

        # 加密数据
        cdata = data.encode("utf8")

        # 加密
        bytes_data = cls.encrypt(cdata, public_key)

        # 转换为base64编码
        b64_data = Base64.encode_str(bytes_data)

        # 返回base64编码
        return b64_data

    @classmethod
    @TypeTool.type_assert
    def decrypt(cls,
                edata: [str, bytes, bytearray],
                private_key: [str, bytes, bytearray] = None) -> bytes:
        """
        RSA数据解密
        :param edata: 要解密的数据
        :param private_key: 私钥
        :return: 解密后的数据
        """
        # 默认使用private.pem作为私钥
        if private_key is None:
            if os.path.exists("private.pem"):
                with open("private.pem", "rb") as f:
                    private_key = f.read()

        error_return = bytes()
        try:
            # 将要解密的数据转换为字节数组
            edata = TypeTool.type_sbb_2_bytes(edata)

            # 将私钥转换为字节数组
            rsa_key = TypeTool.type_sbb_2_bytes(private_key)

            # 验证数据的长度是否正确
            if len(edata) % 256 != 0:
                return error_return

            # 导入私钥
            pkey = RSA.import_key(rsa_key)

            # 创建cipher
            rsa_cipher = PKCS1_OAEP.new(pkey)

            # 分块进行解密
            tlen = len(edata)
            right_return = bytearray()
            sindex = 0
            while sindex < tlen:
                right_return.extend(rsa_cipher.decrypt(edata[sindex:sindex + 256]))
                sindex = sindex + 256

            # 返回解密后的数据
            return bytes(right_return)
        except Exception as e:
            print(e)
            traceback.print_exc()

            # 错误返回空字节数组
            return error_return

    @classmethod
    def decrypt_str(cls,
                    data: str,
                    private_key_path: str = "private.pem") -> str:
        """
        解密文本
        :param data: 要解密的数据
        :param private_key_path: 私钥文件路径
        :return: 解密后的字符串
        """
        # 将数据进行base64解码
        b64_data = Base64.decode(data)
        print("b64_data === ", b64_data)

        # 加载私钥
        private_key = bytes()
        if os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                private_key = f.read()
        else:
            return ""

        # 解密
        result_bytes = cls.decrypt(b64_data, private_key)

        # 将解密后的数据转换为字符串
        return result_bytes.decode("utf-8")
