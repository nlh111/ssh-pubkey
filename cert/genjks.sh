# convert the crt and key to pkcs12 format
openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12 -name server -CAfile ca.crt -caname root -
# convert the pkcs12 format to jks format
keytool -importkeystore -deststorepass nlh1997 -destkeypass nlh1997 -destkeystore server.jks -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass nlh1997 -alias server