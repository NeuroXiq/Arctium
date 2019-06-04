1. [ Overview ](#overview)
2. [ Examples ](#examples)
  - 2.1 [HTTPS to google](#https-to-google)
  - 2.2 [Session resumption](#session-resumption)
  - 2.3 [Client Sni Extension](#client-sni-extension)
  - 2.4 [Client ALPN Extension](#client-alpn-extension)
  - 2.5 [TLS server](#tls-server)
  - 2.6 [Server ALPN Extension](#server-alpn-extension)
  - 2.7 [Server Sni Extension](#server-sni-extension)

## Overview

**Namespaces:**
* Arctium.Connection.Tls:
  - TlsClientConnection - Contains basic configuration used to connect to the server by TLS client
  - TlsServerConnection - Contains basic configuration to accept TLS clients connections 
  - TlsConnectionResult - Returns connection data
  - TlsStream - Read/Write over TLS tunnel

* Arctium.Connection.Tls.Exceptions:
  * FatalAlertException - Exception is thrown when during processing TLS operations occur some error.
  * ReceivedFatalAlertException - Exception is thrown when received Alert message of fatal level
  * ReceiveWarningAlertException - Exception is thrown when received Aler message of warning level
  >*note: server and client connection do not handle warning alerts, any level of alert always gives exception and terminate connection processing. Maybe in future there will be some warning alerts mechanism*

* Arctium.Connection.Tls.Configuration:
  *Contains definition to explicit TLS client/server configuration. Currently this do not work well and can be ignored*
* Arctium.Connection.Tls.Configuration.TlsExtensions:
  * AlpnExtension - ALPN extension support for client/server
  * SniExtension - Server name extension support (currently only for client)

<a name="clientcodeexamples"/>

## Client code examples


## HTTPS to google

```cs

using Arctium.Connection.Tls;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TlsExamples
{
    //see using statement

    class TlsExampleClientConnection
    {
        //create connected socket to any server supporting TLS 1.2
        static Socket ConnectToGoogleCom()
        {
            IPAddress ip = Dns.GetHostEntry("www.google.com").AddressList[0];
            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(ip, 443);

            return socket;
        }

        //get any request to show how application data exchange works (read and write)
        static byte[] GetExampleHttpRequest()
        {
            string request =  "GET / HTTP/1.1\r\n" +
                "Host: www.google.com\r\n\r\n";

            return Encoding.ASCII.GetBytes(request);
        }

        public static void Main(string[] args)
        {
            Socket connectedSocket = ConnectToGoogleCom();
            //create inner stream
            Stream networkStream = new NetworkStream(connectedSocket);
            
            // configure client connection (implicit configuration in ctor of this class)
            TlsClientConnection tlsClientConnection = new TlsClientConnection();

            //now, after configuring client connection connect on this implicitly defined configuration
            // to server usign 'networkStream' created from socket above
            TlsConnectionResult tlsConnectionResult = tlsClientConnection.Connect(networkStream);

            //tlsConnectionResult holds some additional data 
            //but now most important field is 'TlsStream'

            TlsStream stream = tlsConnectionResult.TlsStream;

            //TlsStream is 'normal' stream and now something can be readed from it or writed to it

            //get some bytes to write over created tls tunnel
            byte[] requestBytes = GetExampleHttpRequest();

            //write this request first
            stream.Write(requestBytes, 0, requestBytes.Length);

            //now prepare to read some data
            byte[] buffer = new byte[0x4000];
            int readedBytes = stream.Read(buffer, 0, 0x4000);

            // see that requests string in method above uses HTTP/1.1 - text protocol,
            // can convert response to string and write to the console window
            string responseString = Encoding.ASCII.GetString(buffer, 0, readedBytes);

            Console.WriteLine("Fragment of the response from TLS tunnel:\n");
            Console.WriteLine(responseString);

            //send close notify
            //now TLS connection is closed
            stream.Close();

            //close connection on socket
            connectedSocket.Close();

            //end work
        }

        /*
         [Console Output]:
         
         Fragment of the response from TLS tunnel:

         HTTP/1.1 200 OK
         Date: Wed, 29 May 2019 17:22:13 GMT
         Expires: -1
         Cache-Control: private, max-age=0
         Content-Type: text/html; charset=ISO-8859-1
         P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
         Server: gws
         X-XSS-Protection: 0
         X-Frame-Options: SAMEORIGIN
         Set-Cookie: 1P_JAR=2019-05-29-17; expires=Fri, 28-Jun-2019 17:22:13 GMT; path=/; domain=.google.com [... more data ...]
         
         */
    }
}
```

## Session resumption

```cs
using Arctium.Connection.Tls;
using Arctium.Connection.Tls.Configuration;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TlsExamples
{
    //see using statement

    class TlsExampleClientConnection
    {
        //create connected socket to any server supporting TLS 1.2
        static Socket ConnectToGoogleCom()
        {
            IPAddress ip = Dns.GetHostEntry("www.google.com").AddressList[0];
            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(ip, 443);

            return socket;
        }

        //get any request to show how application data exchange works (read and write)
        static byte[] GetExampleHttpRequest()
        {
            string request =  "GET / HTTP/1.1\r\n" +
                "Host: www.google.com\r\n\r\n";

            return Encoding.ASCII.GetBytes(request);
        }

        //compare 2 bytes arrays contains session id and write if they are same or not
        static void SessionIsResumed(byte[] sesId1, byte[] sesId2)
        {
            bool isResumed = true;
            if (sesId1.Length == sesId2.Length)
            {
                for (int i = 0; i < sesId1.Length; i++)
                {
                    if (sesId1[i] != sesId2[i])
                    {
                        isResumed = false;
                    }
                }
            }
            else isResumed = false;


            if (isResumed)
            {
                Console.WriteLine("Session is resumed success. SessionsID are same");
            }
            else
            {
                Console.WriteLine("Session is not resumed. SessionID are different");
            }

        }

        public static void Main(string[] args)
        {
            //create several connection to one server
            Socket connectedSocket1 = ConnectToGoogleCom();
            Socket connectedSocket2 = ConnectToGoogleCom();
            Socket connectedSocket3 = ConnectToGoogleCom();

            Stream innerStream1 = new NetworkStream(connectedSocket1);
            Stream innerStream2 = new NetworkStream(connectedSocket2);
            Stream innerStream3 = new NetworkStream(connectedSocket3);
            

            TlsClientConnection clientConnections = new TlsClientConnection();

            //full-handshake connection

            TlsConnectionResult result1 = clientConnections.Connect(innerStream1);
            Tls12Session cachedSession = result1.Session;

            //trying to resume session connected on innerStream1 over connectedSocket1 socket

            //this step can be repeated more times as needed to more that 2 connections
            // there can be innerStream4,5 ... to every new connected socket
            TlsConnectionResult result2 = clientConnections.Connect(innerStream2, cachedSession);
            TlsConnectionResult result3 = clientConnections.Connect(innerStream3, cachedSession);

            //note: if session is not resumed, TLS connection is going to full-handshake
            //and will be establshed without resumption 

            Console.WriteLine("Session resumption example result: ");
            SessionIsResumed(result1.Session.SessionID, result2.Session.SessionID);
            SessionIsResumed(result1.Session.SessionID, result3.Session.SessionID);

            //stream to write app data e.g. http/1.1 requests:
            TlsStream stream1 = result1.TlsStream;
            TlsStream stream2 = result2.TlsStream;
            TlsStream stream3 = result3.TlsStream;

            //Out:
            /*
             Session resumption example result:
             Session is resumed success. SessionsID are same
             Session is resumed success. SessionsID are same
             */


        }


    }
}

```
## Client Sni Extension



## Client ALPN Extension

```cs
using Arctium.Connection.Tls;
using Arctium.Connection.Tls.Configuration.TlsExtensions;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TlsExamples
{
    //see using statement

    class TlsExampleClientConnection
    {
        //create connected socket to any server supporting TLS 1.2
        static Socket ConnectToGoogleCom()
        {
            IPAddress ip = Dns.GetHostEntry("www.google.com").AddressList[0];
            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(ip, 443);

            return socket;
        }

        //get any request to show how application data exchange works (read and write)
        static byte[] GetExampleHttpRequest()
        {
            string request = "GET / HTTP/1.1\r\n" +
                "Host: www.google.com\r\n\r\n";

            return Encoding.ASCII.GetBytes(request);
        }

        public static void Main(string[] args)
        {
            Socket connectedSocket = ConnectToGoogleCom();
            //create inner stream
            Stream networkStream = new NetworkStream(connectedSocket);

            string[] protocols = new string[] { "http/1.1", "http/1.0" };

            //prtocol names to send in client hello extension
            AlpnExtension alpnExtension = new AlpnExtension(protocols);
            TlsHandshakeExtension[] extensionsToSend = new TlsHandshakeExtension[] { alpnExtension };

            TlsClientConnection tlsClientConnection = new TlsClientConnection(extensionsToSend);

            TlsConnectionResult tlsConnectionResult = tlsClientConnection.Connect(networkStream);

            //* reponse can be null - server do not accept alpn extesnion
            //* response can have other extensions than sended, server do not accept extension
            //  which was sended but provided others supported by them
            //
            TlsHandshakeExtension[] extensionsResponse = tlsConnectionResult.ExtensionsResult;

            if (extensionsResponse != null)
            {
                //sended only 1 extensions, expected result that first element containt response

                TlsHandshakeExtension extension = extensionsResponse[0];
                if (extension.Type == TlsHandshakeExtension.ExtensionType.ALPN)
                {
                    AlpnExtension response = (AlpnExtension)extension;
                    Console.WriteLine("response to ALPN: ");
                    Console.WriteLine(response.SelectedProtocolName);
                }
            }

            Stream tlsStream = tlsConnectionResult.TlsStream;

            //read/write over tls stream
            // ... 
            // ...

            //close notify
            tlsStream.Close();

            //close socket
            connectedSocket.Close();
        }
    }
}

```cs
using Arctium.Connection.Tls;
using Arctium.Connection.Tls.Configuration.TlsExtensions;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TlsExamples
{
    //see using statement

    class TlsExampleClientConnection
    {
        //create connected socket to any server supporting TLS 1.2
        static Socket ConnectToGoogleCom()
        {
            IPAddress ip = Dns.GetHostEntry("www.google.com").AddressList[0];
            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(ip, 443);

            return socket;
        }

        //get any request to show how application data exchange works (read and write)
        static byte[] GetExampleHttpRequest()
        {
            string request = "GET / HTTP/1.1\r\n" +
                "Host: www.google.com\r\n\r\n";

            return Encoding.ASCII.GetBytes(request);
        }

        public static void Main(string[] args)
        {
            Socket connectedSocket = ConnectToGoogleCom();
            //create inner stream
            Stream networkStream = new NetworkStream(connectedSocket);

            string[] protocols = new string[] { "http/1.1", "http/1.0" };

            SniExtension sniExtension = new SniExtension("www.google.com");
            TlsHandshakeExtension[] extensionsToSend = new TlsHandshakeExtension[] { sniExtension };

            TlsClientConnection tlsClientConnection = new TlsClientConnection(extensionsToSend);

            TlsConnectionResult tlsConnectionResult = tlsClientConnection.Connect(networkStream);

            Stream tlsStream = tlsConnectionResult.TlsStream;

            //read/write over tls stream
            // ... 
            // ...

            //close notify
            tlsStream.Close();

            //close socket
            connectedSocket.Close();
        }
    }
}
```

## TLS server

```cs
using Arctium.Connection.Tls;
using Arctium.Connection.Tls.Configuration.TlsExtensions;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsExamples
{
    //see using statement

    class TlsServer
    {
        static Socket CreateServerSocket()
        {
            Socket server = new Socket(SocketType.Stream, ProtocolType.Tcp);
            server.Bind(new IPEndPoint(IPAddress.Any, 443));
            server.Listen(1234);

            return server;
        }

        static Socket AcceptClientFromsServerSocket(Socket serverSock)
        {
            return serverSock.Accept();
        }

        public static void Main(string[] args)
        {
            Socket serverSocket = CreateServerSocket();
            Socket clientSocket = AcceptClientFromsServerSocket(serverSocket);

            NetworkStream clientInnerStream = new NetworkStream(clientSocket);

            X509Certificate2 serverCertificate = new X509Certificate2("D:\\test.pfx", "test");

            TlsServerConnection serverConnection = new TlsServerConnection(serverCertificate);
            TlsConnectionResult result = serverConnection.Accept(clientInnerStream);

            //ready stream in result

            TlsStream stream = result.TlsStream;

            //connected on web browser, url: https://localhost

            byte[] request = new byte[0x400];

            int readedBytes = stream.Read(request, 0, 0x400);

            string requestString = Encoding.ASCII.GetString(request, 0, readedBytes);

            Console.WriteLine("Request from browser: ");
            Console.WriteLine(requestString);

            //send close notify
            stream.Close();

            //close networkstream and socket
            clientInnerStream.Close();

            //end

            // [Console out] 
            //
            //Request from browser:
            //GET / HTTP / 1.1
            //Host: localhost
            //User - Agent: Mozilla / 5.0(Windows NT 6.3; Win64; x64; rv: 67.0) Gecko / 20100101 Firefox / 67.0
            //Accept: text / html,application / xhtml + xml,application / xml; q = 0.9,*/*;q=0.8
            //Accept-Language: en-US,en;q=0.5
            //Accept-Encoding: gzip, deflate, br
            //Connection: keep-alive
            //Upgrade-Insecure-Requests: 1
        }
    }
}
```

## Server ALPN Extension

```cs
using Arctium.Connection.Tls;
using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Configuration.TlsExtensions;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsExamples
{
    //see using statement

    class TlsServer
    {
        static Socket CreateServerSocket()
        {
            Socket server = new Socket(SocketType.Stream, ProtocolType.Tcp);
            server.Bind(new IPEndPoint(IPAddress.Any, 1234));
            server.Listen(1234);

            return server;
        }

        static Socket AcceptClientFromsServerSocket(Socket serverSock)
        {
            return serverSock.Accept();
        }

        public static void Main(string[] args)
        {
            Socket serverSocket = CreateServerSocket();
            Socket clientSocket = AcceptClientFromsServerSocket(serverSocket);

            NetworkStream clientInnerStream = new NetworkStream(clientSocket);

            X509Certificate2 serverCertificate = new X509Certificate2("D:\\test.pfx", "test");

            string[] supportedProtocols = new string[] { "http/1.1", "http/1.0" };
            AlpnExtension alpnExtensions = new AlpnExtension(supportedProtocols);
            TlsHandshakeExtension[] extensionsList = new TlsHandshakeExtension[] { alpnExtensions };

            //must be tls12
            TlsServerConnection serverConnection = new TlsServerConnection(serverCertificate, TlsProtocolVersion.Tls12, extensionsList );
            TlsConnectionResult result = serverConnection.Accept(clientInnerStream);
            TlsHandshakeExtension[] extensionsResult = result.ExtensionsResult;

            if (extensionsResult != null)
            {
                if (extensionsResult[0].Type == TlsHandshakeExtension.ExtensionType.ALPN)
                {
                    Console.WriteLine("selected protocol: ");
                    AlpnExtension alpnResult = (AlpnExtension)extensionsResult[0];
                    Console.WriteLine(alpnResult.SelectedProtocolName);
                }
            }

            //ready stream in result

            TlsStream stream = result.TlsStream;

            //connected on web browser, url: https://localhost

            byte[] request = new byte[0x400];

            int readedBytes = stream.Read(request, 0, 0x400);

            string requestString = Encoding.ASCII.GetString(request, 0, readedBytes);

            Console.WriteLine("Request from browser: ");
            Console.WriteLine(requestString);

            //send close notify
            stream.Close();

            //close networkstream and socket
            clientInnerStream.Close();

            //end

            //[Console Out]
            //
            //
            //selected protocol:
            //http / 1.1
            //Request from browser:
            //GET / HTTP / 1.1
            //Host: 78.10.151.161:1234
            //User - Agent: Mozilla / 5.0(Windows NT 6.3; Win64; x64; rv: 67.0) Gecko / 20100101 Firefox / 67.0
            //Accept: text / html,application / xhtml + xml,application / xml; q = 0.9,*/*;q=0.8
            //Accept-Language: en-US,en;q=0.5
            //Accept-Encoding: gzip, deflate, br
            //Connection: keep-alive
            //Cookie: rg_cookie_session_id=7A6FF4C15DB31FE7
            //Upgrade-Insecure-Requests: 1
        }

        
    }
}
```


## Server Sni Extension

```cs
using Arctium.Connection.Tls;
using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Configuration.TlsExtensions;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsExamples
{
    //see using statement

    class TlsServer
    {
        static Socket CreateServerSocket()
        {
            Socket server = new Socket(SocketType.Stream, ProtocolType.Tcp);
            server.Bind(new IPEndPoint(IPAddress.Any, 1234));
            server.Listen(1234);

            return server;
        }

        static Socket AcceptClientFromsServerSocket(Socket serverSock)
        {
            return serverSock.Accept();
        }

        public static void Main(string[] args)
        {
            Socket serverSocket = CreateServerSocket();
            Socket clientSocket = AcceptClientFromsServerSocket(serverSocket);

            NetworkStream clientInnerStream = new NetworkStream(clientSocket);

            //certificate will be sended when client do not support SNI or 
            //if SNI not match in client request and provided Cert-names pairs below
            X509Certificate2 defaultCertificate = new X509Certificate2("D:\\test.pfx", "test");

            SniExtension.CertNamePair[] certNamePairs = new SniExtension.CertNamePair[]
            {
                new SniExtension.CertNamePair(new X509Certificate2("D:\\test2.pfx","test2"), "test2host"),
                new SniExtension.CertNamePair(new X509Certificate2("D:\\test3.pfx","test3"), "test3host"),
            };

            SniExtension serverSniExtension = new SniExtension(certNamePairs);

            TlsHandshakeExtension[] extensions = new TlsHandshakeExtension[] { serverSniExtension };

            TlsServerConnection serverConnection = new TlsServerConnection(defaultCertificate, TlsProtocolVersion.Tls12, extensions );

            //
            // server choose appriopriate certificate to send

            TlsConnectionResult result = serverConnection.Accept(clientInnerStream);
            TlsHandshakeExtension[] extensionsResult = result.ExtensionsResult;


            TlsStream stream = result.TlsStream;

            //send close notify
            stream.Close();

            //close networkstream and socket
            clientInnerStream.Close();

           
        }

        
    }
}
```



