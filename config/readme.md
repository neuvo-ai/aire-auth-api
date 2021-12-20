Configuration file format

```json
{
        "mongo": {
                "uri": "mongosrv",
        },
        "server": {
                "jwt": {
                        "issuer": "issuer_name",
                        "IssuerRefresh": "issuer-refresh",
                },
                "auth": "standard"
        },
        "keyLocation": {
                "private": "keys/api.rsa",
                "public": "keys/api.rsa.pub"
        }
}
```
