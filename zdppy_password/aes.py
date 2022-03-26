# import base64
# from .libs.Crypto.Cipher import AES
#
# AES_SECRET_KEY = '_ZhangDapeng520%'  # 此处16|24|32个字符
# IV = "1234567890123456"
#
# # padding算法
# BS = len(AES_SECRET_KEY)
# pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
# unpad = lambda s: s[0:-ord(s[-1:])]
#
#
# class Aes(object):
#     def __init__(self, key: str = None, encoding: str = "utf8"):
#         """
#         初始化Aes加密对象
#         :param key: 加密的key
#         :param encoding: 字符串编码
#         """
#         self.encoding = encoding  # 字符串编码
#         self.ciphertext = None  # 加密后的文本
#         self.key = AES_SECRET_KEY  # 加密的key
#         if key is not None:
#             self.key = key
#         self.mode = AES.MODE_CBC  # 加密的模式
#
#     def encrypt(self, text, is_to_str: bool = True):
#         """
#         加密
#         :param text 要加密的文本
#         :param is_to_str 是否转换为字符串
#         :return: AES加密后的文本
#         """
#         # 生成cryptor
#         cryptor = AES.new(self.key.encode(self.encoding), self.mode, IV.encode(self.encoding))
#
#         # 加密文本
#         self.ciphertext = cryptor.encrypt(bytes(pad(text), encoding=self.encoding))
#
#         # AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题，使用base64编码
#         result = base64.b64encode(self.ciphertext)
#
#         if is_to_str:
#             return result.decode(self.encoding)
#
#         # 返回结果
#         return result
#
#     # 解密函数
#     def decrypt(self, text, is_to_str: bool = True):
#         """
#         加密AES加密后的文本
#         :param text: AES加密后的文本
#         :param is_to_str 是否转换为字符串
#         :return: AES解密后的文本
#         """
#         # base64解码
#         decode = base64.b64decode(text)
#
#         # 创建cryptor
#         cryptor = AES.new(self.key.encode(self.encoding), self.mode, IV.encode(self.encoding))
#
#         # 解密文本
#         plain_text = cryptor.decrypt(decode)
#         result = unpad(plain_text)
#
#         # 转换为字符串
#         if is_to_str:
#             result = result.decode(self.encoding)
#
#         # 返回解密后的结果
#         return result
#
#
# if __name__ == '__main__':
#     aes = Aes()
#     data = "{'name':'zhangdapeng'}"
#     t = aes.encrypt(data)
#     print(t)
#     print(aes.decrypt(t))
