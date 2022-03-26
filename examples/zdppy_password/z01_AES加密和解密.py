from zdppy_password.aes import Aes

aes = Aes()
data = "{'name':'zhangdapeng'}"
t = aes.encrypt(data)
print(t)
print(aes.decrypt(t))
