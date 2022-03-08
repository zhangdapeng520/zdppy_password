from zdppy_password.aes import AES_ENCRYPT

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
