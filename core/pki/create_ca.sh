openssl genrsa -out ca.key 4096
openssl req -new -key ca.key -out ca.csr
openssl x509 -req -days 3650 -in ca.csr -signkey ca.key -out ca.crt
