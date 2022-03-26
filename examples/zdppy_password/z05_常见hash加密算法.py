from zdppy_password.hash import *

# 不加盐
print(md5("123456"))
print(md5_verify("123456", md5("123456")))

# 加盐
print(md5("123456", "salt"))
print(md5_verify("123456", md5("123456", "salt"), "salt"))

# 不加盐
print(sha1("abc"))
print(sha1_verify("123456", sha1("123456")))

# 加盐
print(sha1("123456", "salt"))
print(sha1_verify("123456", sha1("123456", "salt"), "salt"))

# 不加盐
print(sha256("abc"))
print(sha256_verify("123456", sha256("123456")))

# 加盐
print(sha256("123456", "salt"))
print(sha256_verify("123456", sha256("123456", "salt"), "salt"))

# 不加盐
print(sha512("abc"))
print(sha512_verify("123456", sha512("123456")))

# 加盐
print(sha512("123456", "salt"))
print(sha512_verify("123456", sha512("123456", "salt"), "salt"))
