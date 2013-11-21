openssl genrsa -out cakey.pem 4096
openssl req -new -x509 -extensions v3_ca -key cakey.pem -out cacert.pem -days 3650

