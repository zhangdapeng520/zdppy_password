from .libs import rsa


class Rsa:
    def __init__(
            self,
            key_length: int = 512,
    ):
        """
        初始化Rsa加密对象
        :param key_length: 生成key的长度，长度越长越安全，但是速度也越慢
        """
        self.private_key = None  # 私钥
        self.public_key = None  # 公钥
        self.public_key, self.private_key = rsa.newkeys(key_length)

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

    def signature(self, data, private_key, is_hash: bool = False):
        """
        签名
        :param data: 要签名的数据
        :param private_key: 私钥
        :param is_hash: 是否hash
        :return:
        """
        # 结果
        result = None

        # 转换为字节数组
        if not isinstance(data, bytes):
            data = data.encode("utf8")

        # hash
        if is_hash:
            data = rsa.compute_hash(data, "SHA-1")
            result = rsa.sign_hash(data, private_key, "SHA-1")
        else:
            result = rsa.sign(data, private_key, 'SHA-1')

        # 返回结果
        return result

    def verify(self, data, signature, public_key):
        """
        校验签名
        :param data: 签名的数据
        :param signature: 签名对象
        :param public_key: 公钥
        :return: 校验结果，一个布尔值
        """
        # 返回结果
        result = True

        # 转换为字节数组
        if isinstance(data, str):
            data = data.encode("utf8")

        # 校验参数
        if not isinstance(data, bytes):
            # TODO: 不是字节数组
            pass

        # 校验签名
        try:
            result = rsa.verify(data, signature, public_key)
            if result != "SHA-1":
                result = False
        except Exception as e:
            print(e)
            result = False

        # 返回结果
        return result
