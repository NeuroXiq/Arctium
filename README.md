## WORK IN PROGRESS
Arctium will be a simple TLS protocol implementation written in C#. 
Implemented standards (or not implemented yet):

|Version | TLS 1.1 | TLS 1.2 |TLS 1.2 Extensions| TLS 1.3|
|:--------:|:---------:|:-----------------:|:-------------:|:--------:|
|Standard |[RFC 4346]  |[RFC 5246]         |[RFC 6066]     |[RFC 8446]|
|Status|Not implemented|Partial implemented|Not implemented|Not implemented|

- **Tls v1.1:** Not working code, 'handshake' on server side works to 'finished' (including sending/receiving this message)

- **Tls v1.2:** Connection can be established on server side, client authentication and extensions are not available.
  
- **Tls v1.3:  Not implemented**


For more informations about TLS connection see: [Tls docs]

[RFC 4346]:<https://www.ietf.org/rfc/rfc4346.txt>
[RFC 5246]:<https://www.ietf.org/rfc/rfc5246.txt>
[RFC 6066]:<https://tools.ietf.org/html/rfc6066>
[RFC 8446]:<https://tools.ietf.org/html/rfc8446>
[Tls docs]:<docs/Tls/Connection>