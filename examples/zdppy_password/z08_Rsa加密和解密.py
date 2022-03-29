from zdppy_password import Rsa, Base64
import json

rsa = Rsa()

data = {"username": "张大鹏", "age": 22}
data = json.dumps(data)
print(data)

# 加密
secret = rsa.encrypt_str(data)
print("加密：", secret)

# 解密
result = rsa.decrypt_str(secret)
print("===", result)
print("===", json.loads(result))

# 从go复制过来的
data = "j+Lc1OtOu+rF9d+cKvU7IUmQ/WNTQk20t5mEABcT2liWPic2KIuF8jbQrstBdvh7zmj1KIYf5z6PD9CNCfLPnthD6k1+tLVBWPkCj3x6LVrURInJRJTHh6QrcvxM1ZmT563/D0okw9O0cr8Qc3nMDT2/dUTEpzShT3dPG76ztoX4nSd4MMEbBIOTT3G7deglwMZNDVMfUmgLz2WTa2lijfTrL7rpGcD0ofeqjUXmYPo6OV0dQV6A1myJqcSHTGNcmwvaZhGVxrKW87nB5ZJnZcYkLfpm+1YFr93iR+Qj1ygjhTqnX5pwxyoNg090/1omvXYv8jSq2mhArAVncRl7KA=="
print(rsa.decrypt(Base64.decode(data)).decode("utf-8"))
