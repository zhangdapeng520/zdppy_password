# zdppy_password
Python密码工具

## 常用命令
生成私钥
```shell
openssl genrsa -out private.pem 1024
```

生成公钥
```shell
openssl rsa -in private.pem -pubout -out public.pem
```
