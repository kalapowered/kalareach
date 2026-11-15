#!/bin/bash
# make-certs.sh DIR
# Makes a certificate authority and a leaf certificate for https://127.0.0.1 in DIR (mode 0700):
# ca.pem, leaf.pem (the leaf and its authority), leaf.key. Prints no key.
set -eu
dir=${1:?usage: make-certs.sh DIR}
umask 077
install -d -m 0700 "$dir"
cd "$dir"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 2 -subj '/CN=sandbox probe authority' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -subj '/CN=127.0.0.1' -out leaf.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n' >ext.cnf
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -sha256 -extfile ext.cnf -out leaf-only.pem
cat leaf-only.pem ca.pem >leaf.pem
openssl verify -CAfile ca.pem leaf-only.pem >/dev/null
echo "make-certs: done"
