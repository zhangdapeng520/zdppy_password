# zdppy_password
Python密码工具

## 常用命令
生成私钥
```shell
openssl genrsa -out rsa_private_key.pem 1024
```

生成公钥
```shell
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```
