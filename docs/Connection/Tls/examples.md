1. [ Overview ](#overview)
2. [ Client code examples ](#clientcodeexamples)

<a name="overview"/>

## Overview

**Namespaces:**
* Arctium.Connection.Tls:
  * TlsClientConnection - Contains basic configuration used to connect to the server by TLS client
  * TlsServerConnection - Contains basic configuration to accept TLS clients connections 
  * TlsConnectionResult - Returns connection data
  * TlsStream - Read/Write over TLS tunnel

* Arctium.Connection.Tls.Exceptions:
  * FatalAlertException - Exception is thrown when during processing TLS operations occur some error.
  * ReceivedFatalAlertException - Exception is thrown when received Alert message of fatal level
  * ReceiveWarningAlertException - Exception is thrown when received Aler message of warning level
  * note: server and client connection do not handle warning alerts, any level of alert always gives exception and terminate connection processing. Maybe in future there will be some warning alerts mechanism*

* Arctium.Connection.Tls.Configuration:
  *Contains definition to explicit TLS client/server configuration. Currently this do not work well and can be ignored*
* Arctium.Connection.Tls.Configuration.TlsExtensions:
  * AlpnExtension - ALPN extension support for client/server
  * SniExtension - Server name extension support (currently only for client)

<a name="clientcodeexamples"/>

## Client code examples


