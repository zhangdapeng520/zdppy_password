import base64
from Crypto.Cipher import AES
from urllib import parse

AES_SECRET_KEY = 'lingyejunAesTest'  # 此处16|24|32个字符
IV = "1234567890123456"

# padding算法
BS = len(AES_SECRET_KEY)
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1:])]


class AES_ENCRYPT(object):
    def __init__(self):
        self.key = AES_SECRET_KEY
        self.mode = AES.MODE_CBC

    # 加密函数
    def encrypt(self, text):
        cryptor = AES.new(self.key.encode("utf8"), self.mode, IV.encode("utf8"))
        self.ciphertext = cryptor.encrypt(bytes(pad(text), encoding="utf8"))
        # AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题，使用base64编码
        return base64.b64encode(self.ciphertext)

    # 解密函数
    def decrypt(self, text):
        decode = base64.b64decode(text)
        cryptor = AES.new(self.key.encode("utf8"), self.mode, IV.encode("utf8"))
        plain_text = cryptor.decrypt(decode)
        return unpad(plain_text)


if __name__ == '__main__':
    aes_encrypt = AES_ENCRYPT()
    my_email = "lingyejun@python.aes"
    e = aes_encrypt.encrypt(my_email)
    d = aes_encrypt.decrypt(e)
    print(my_email)
    print(e)
    print(d, d.decode("utf8"))

    # 测试解密java
    java_encode = "tFFcpB/IeI78OWnPjD+sIXYlFqFgcW1Yyk1naa46uT0=".encode("utf8")
    print("解密java：", aes_encrypt.decrypt(java_encode).decode())
