from zdppy_password.aes_py_go import AesPyGo

apg = AesPyGo()
res = apg.encrypt(b'{"cmd": 3000, "msg": "ok"}').decode(encoding='utf-8')
print(res)
print(apg.decrypt(res))

# 从go复制过来的
print(apg.decrypt("0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="))
