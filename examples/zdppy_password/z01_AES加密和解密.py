from zdppy_password.aes import Aes

aes = Aes()
res = aes.encrypt(b'{"cmd": 3000, "msg": "ok"}').decode(encoding='utf-8')
print(res)
print(aes.decrypt(res))

# 从go复制过来的
print(aes.decrypt("0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="))
