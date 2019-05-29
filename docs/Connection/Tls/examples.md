1. [ Overview ](#overview)
2. [ Client code examples ](#clientcodeexamples)
  2.1 [ HTTPS/1.1 to www.google.com ](#https11togoogle)

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
  * *note: server and client connection do not handle warning alerts, any level of alert always gives exception and terminate connection processing. Maybe in future there will be some warning alerts mechanism*

* Arctium.Connection.Tls.Configuration:
  *Contains definition to explicit TLS client/server configuration. Currently this do not work well and can be ignored*
* Arctium.Connection.Tls.Configuration.TlsExtensions:
  * AlpnExtension - ALPN extension support for client/server
  * SniExtension - Server name extension support (currently only for client)

<a name="clientcodeexamples"/>

## Client code examples

<a name="https11togoogle"/>

### HTTPS/1.1 to www.google.com

``cs
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
            //now TLS(!) connection is closed
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
``cs