# Generating keys

**Generate 2048bit private key**
```
openssl genrsa -out api.rsa 2048
```

**Generate public key**
```
openssl rsa -in api.rsa -pubout > api.rsa.pub
```


