from .type_tool import TypeTool
import base64
import traceback


class Base64:
    @classmethod
    @TypeTool.type_assert
    def encode(cls, cdata: [str, bytes, bytearray]) -> bytes:
        """
        base64编码
        :param cdata: 要编码的数据
        :return: 编码后的字符串
        """
        error_return = bytes()
        try:
            # 将数据转换为字节数组
            cdata = TypeTool.type_sbb_2_bytes(cdata)

            # 进行base64编码并返回
            return base64.b64encode(cdata)
        except Exception as e:
            print(e)
            traceback.print_exc()
            return error_return

    @classmethod
    def encode_str(cls, cdata: [str, bytes, bytearray]) -> str:
        """
        编码数据并转换为字符串
        :param cdata: 要编码的数据
        :return: 编码后的字符串
        """
        return cls.encode(cdata).decode('utf-8')

    @classmethod
    @TypeTool.type_assert
    def decode(cls, edata: [str, bytes, bytearray]) -> bytes:
        """
        base64解码
        :param edata:要解码的数据
        :return: 解码后的数据
        """
        error_return = bytes()
        try:
            edata = TypeTool.type_sbb_2_bytes(edata)
            return base64.b64decode(edata)
        except Exception as e:
            print(e)
            traceback.print_exc()
            return error_return

    @classmethod
    def decode_str(cls, edata: [str, bytes, bytearray]) -> str:
        """
        解码数据，并转换为字符串
        :param edata: 要解码的数据
        :return: 解码后的字符串
        """
        return cls.decode(edata).decode('utf-8')
