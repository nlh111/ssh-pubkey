# 生成 ECC 私钥
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ca.key

# 使用私钥生成根证书
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/C=CN/ST=Beijing/L=Beijing/O=Example Inc./OU=IT Department/CN=example.com"

# 为客户端生成一个新的 ECC 私钥并转换为 PKCS#8 格式
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out client.key

# 使用私钥创建证书签名请求（CSR）
openssl req -new -key client.key -out client.csr -subj "/C=CN/ST=Shanghai/L=Shanghai/O=Client/OU=Client Department/CN=client.example.com"

# 使用 CA 的私钥和证书签署 CSR，生成客户端证书
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

# 为服务器生成一个新的 ECC 私钥并转换为 PKCS#8 格式
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out server.key

# 使用私钥创建证书签名请求（CSR）
openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Server/OU=Server Department/CN=server.example.com"

# 使用 CA 的私钥和证书签署 CSR，生成服务器证书
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256  -extensions v3_req -extfile openssl.cnf