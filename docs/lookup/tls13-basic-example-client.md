```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Basic example client connection
 * Example demonstrates how to connect to server using TLS 1.3 client without
 * any specific configuration
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();
            var tlsClient = new Tls13Client(context);
            var networkStream = OpenNetworkStream();

            var tlsStream = tlsClient.Connect(networkStream);

            string request = "GET / HTTP/1.1\r\n" +
                "Host: github.com\r\n" + 
                "Accept: */*\r\n\r\n";

            byte[] toSend = Encoding.ASCII.GetBytes(request);
            byte[] received = new byte[1024];

            tlsStream.Write(toSend);
            tlsStream.Read(received);

            Console.WriteLine(Encoding.ASCII.GetString(received));

            /* [OUTPUT]
             * 
             * HTTP/1.1 200 OK
             * Server: GitHub.com
             * Date: Sun, 06 Nov 2022 04:35:00 GMT
             * Content-Type: text/html; charset=utf-8
             * Vary: X-PJAX, X-PJAX-Container, Turbo-Visit, Turbo-Frame, Accept-Language, Accept-Encoding, Accept, X-Requested-With
             * 
             * [........]
             */
        }

        static NetworkStream OpenNetworkStream()
        {
            var pageIP = Dns.GetHostAddresses("www.github.com")[0];
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(pageIP, 443);

            var networkStream = new NetworkStream(socket);

            return networkStream;
        }
    }
}

```