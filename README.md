## WORK IN PROGRESS
Arctium will be a simple TLS protocol implementation written in C#. 
Implemented standards (or not implemented yet):

|Name           |   Status     | Standard   |
|:-------------:|:------------:|:----------:|
| TLS 1.1       |     X        |[RFC 4346]  |
| TLS 1.2       | Partial      |[RFC 5246]  |
| TLS 1.3       |     X        |[RFC 8446]  |
| TLS Extensions| Partial      |[RFC 6066]  |
| ALPN          | X            |[RFC 7301]  |




- **Tls v1.1:** Not working code, 'handshake' on server side works to 'finished' (including sending/receiving this message)

- **Tls v1.2:** Connection can be established on server side, client authentication and extensions are not available.
  
- **Tls v1.3:  Not implemented**


For more informations about TLS connection see: [Tls docs]
For more informations about connection see: [Tls examples]

[RFC 4346]:<https://www.ietf.org/rfc/rfc4346.txt>
[RFC 5246]:<https://www.ietf.org/rfc/rfc5246.txt>
[RFC 6066]:<https://tools.ietf.org/html/rfc6066>
[RFC 8446]:<https://tools.ietf.org/html/rfc8446>
[RFC 7301]:<https://tools.ietf.org/html/rfc7301>
[Tls docs]:<docs/Connection/Tls/>
[Tls examples]:<docs/Connection/tls/examples.md>