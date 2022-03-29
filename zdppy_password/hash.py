from Crypto.Hash import SHA384
import hashlib
import traceback
from .type_tool import TypeTool
from .hash_func import sha1, sha1_verify, sha256, sha256_verify, sha512, sha512_verify


class Hash:
    sha1 = sha1
    sha1_verify = sha1_verify
    sha256 = sha256
    sha256_verify = sha256_verify
    sha512 = sha512
    sha512_verify = sha512_verify

    @classmethod
    @TypeTool.type_assert
    def hash(cls, s: str) -> int:
        """
        将数据hash化
        :param s: 要hash的数据，可以是字符串，字节数组
        :return: hash后索引
        """
        hn = 0
        try:
            for c in s:  # 将每个字符unicode值
                hn += ord(c)  # 获取unicode值
        except Exception as e:
            print(e)
            traceback.print_exc()
        return hn

    @classmethod
    @TypeTool.type_assert
    def md5(cls,
            s: [str, bytes, bytearray],
            start: int = 8,
            end: int = -8
            ) -> str:
        """
        对数据进行md5加密
        :param s: 要加密的数据
        :param start: 截取hash串的开始索引
        :param end: 截取hash串的结束索引
        :return: 加密后的字符串
        """
        try:
            # 将数据转换为bytes字节数组
            s = TypeTool.type_sbb_2_bytes(s)
        except Exception as e:
            print(e)
            traceback.print_exc()  # 打印详细的错误信息
            return ''

        # 创建md5加密对象
        m = hashlib.md5()

        # 加密数据
        m.update(s)

        # 返回加密后的十六进制字符串，移除前八位和后八位
        return m.hexdigest()[start:end]

    @classmethod
    @TypeTool.type_assert
    def sha384(cls, s: [str, bytes, bytearray]) -> [str]:
        """
        使用sha384加密
        :param s: 要加密的字符串
        :return: 加密后的字符串
        """
        try:
            # 将数据转换为字节数组
            s = TypeTool.type_sbb_2_bytes(s)

            # 创建sha384对象
            h = SHA384.new()

            # 对数据进行加密
            h.update(s)

            # 返回加密后的十六进制字符串
            return h.hexdigest()
        except Exception as e:
            print(e)
            traceback.print_exc()

        # 出错以后返回空字符串
        return ''
