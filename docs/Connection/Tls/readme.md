## WORK IN PROGRESS

Available features: 

#### Standards
|Name                         |   Status     | Standard   |
|:---------------------------:|:------------:|:----------:|
| TLS 1.1                     |     X        |[RFC 4346]  |
| TLS 1.2                     | Partial      |[RFC 5246]  |
| TLS 1.3                     |     X        |[RFC 8446]  |
| ECC Crypto (2006)           |     X        |[RFC 4492]  |
| ECC Crypto (2018)           |     X        |[RFC 8422]  |
| TLS Extensions              | Partial      |[RFC 6066]  |
| ALPN                        |    Yes       |[RFC 7301]  |
| Negotiated FFDHE Parameters |     X        |[RFC 7919]  |

#### Configurable Extensions
 * SNI (Server name)
 * ALPN (Application layer protocol negotiation)


#### Encryption

|Cipher         |    TLS 1.2   |   TLS 1.3    |
|:-------------:|:------------:|:------------:|
|AES            |     YES      |      X       |

### Supported Tls 1.2 cipher suites:
```
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256
```

#### Key exchange

|Algorithm    |  Tls v1.2 |  Tls v1.3 |
|:-----------:|:---------:|:---------:|
|RSA          |Yes        |     X     |
|ECDHE        |     X     |     X     |         

[RFC 8422]:<https://tools.ietf.org/html/rfc8422>
[RFC 7919]:<https://tools.ietf.org/html/rfc7919>
[RFC 4346]:<https://www.ietf.org/rfc/rfc4346.txt>
[RFC 5246]:<https://www.ietf.org/rfc/rfc5246.txt>
[RFC 6066]:<https://tools.ietf.org/html/rfc6066>
[RFC 8446]:<https://tools.ietf.org/html/rfc8446>
[RFC 7301]:<https://tools.ietf.org/html/rfc7301>
[RFC 4492]:<https://tools.ietf.org/html/rfc4492>
[Tls docs]:<docs/Connection/Tls/>