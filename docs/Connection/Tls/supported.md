### TLS Standards         

|TLS Version| Enable |
|:---------:|:------:|
|1.0        |     No |
|1.1        |     No |
|1.2        |Partial |
|1.3        |No      |


### Public Extensions

|Extension Type   |  Status    |
|:---------------:|:----------:|
|ALPN             |   No       |
|Server Name      | partial    |
|                 |            |
  
### Supported algorithms

#### Key exchange

|Algorithm    |  Tls v1.2 |  Tls v1.3 |
|:-----------:|:---------:|:---------:|
|RSA          |Yes        | No        |
|DHE          |No         | No        |
|DH           |No         | No        |
|ECDH         |No         | No        |
|ECDHE        |No         | No        |
|PSK          |No         | No        |
|SRP          |No         | No        |
|Kerberos     |No         | No        |


#### Symmetric Block encryption
|Algorithm    |  Tls v1.2 |  Tls v1.3 |
|:-----------:|:---------:|:---------:|
|DES          | No        | No        |
|TDES	      | No        | No        |
|DES40        | No        | No        |
|AES          | Yes       | No        |
|IDEA         | No        | No        |
|ARIA         | No        | No        |
|Camellia     | No        | No        |


### Default Tls 1.2 cipher suites:
```
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256
```






