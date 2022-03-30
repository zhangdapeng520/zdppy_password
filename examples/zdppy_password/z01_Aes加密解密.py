from zdppy_password import Aes

key = "_ZhangDapeng520%"

aes = Aes()


def gcm_demo():
    # 加密数据
    edata, nonce, tag = aes.encrypt_gcm(b'{"cmd": 3000, "msg": "ok"}', key)
    print(edata, nonce, tag)

    # 解密数据
    print(aes.decrypt_gcm(edata, key, nonce, tag))

    # 字符串
    edata, nonce, tag = aes.encrypt_gcm_str('{"cmd": 3000, "msg": "ok"}', key)
    print(edata, nonce, tag)
    print(aes.decrypt_gcm_str(edata, key, nonce, tag))

    # 从go复制过来的
    data = "fptYo3iBwpjzpGZMaSPOW7FN5ZE6XAoICmI="
    nonce = "sFz8lrVXI7G4I3UPBbwsDA=="
    tag = "Dy8U52SFUcf0uRQ7EEGgdA=="
    print("从go复制过来的: ", aes.decrypt_gcm_str(data, key, nonce, tag))


def default_demo():
    res = aes.encrypt(b'{"cmd": 3000, "msg": "ok"}').decode(encoding='utf-8')
    print(res)
    print(aes.decrypt(res))

    # 从go复制过来的
    print(aes.decrypt("0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="))


if __name__ == '__main__':
    gcm_demo()  # gcm的加密解密方式
    default_demo()  # 默认ecb的加密解密方式
