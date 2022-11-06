```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Basic example server
 * Example demonstrates how to send HTTP response to browser using by Arctium TLS 1.3 server
 * After running this code:
 * 1. Open Web Browser 
 * 2. Connect to 'https://localhost:444'
 * 3. In my browser I got warning that 'page is not save invalid certificate' I click 'advanced -> continue' to force connection
 * 4. Browser connects and shows sample HTML
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
            var certificateWithPrivateKey = Tls13Resources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1;
            var serverContext = Tls13ServerContext.Default(new[] { certificateWithPrivateKey });
            var tlsServer = new Tls13Server(serverContext);

            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 444));
            socket.Listen(20);

            while (true)
            {
                try
                {
                    var rawSocket = socket.Accept();
                    var networkStream = new NetworkStream(rawSocket);

                    var tlsStream = tlsServer.Accept(networkStream);

                    Task.Factory.StartNew((state) => HandleRequest((Tls13Stream)state), tlsStream);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error");
                    Console.WriteLine(e.Message);
                }
            }
        }

        static void HandleRequest(Tls13Stream tlsStream)
        {
            byte[] read = new byte[1024];
            string htmlResponse = "<html><head></head><body><h1>Arctium TLS 1.3 Server </h1> <h2>- Hello World</h2></body></html>";

            tlsStream.Read(read);

            string partOfRequest = Encoding.ASCII.GetString(read);
            Console.WriteLine("Part of request received: ");
            Console.WriteLine(partOfRequest);

            string write = " HTTP/1.1 200 OK\r\n" +
                "Server: GitHub.com\r\n" + 
                $"Content-Length: {htmlResponse.Length}\r\n\r\n" + 
                htmlResponse;

            byte[] bytesToWrite = Encoding.ASCII.GetBytes(write);
            tlsStream.Write(bytesToWrite);

            Console.WriteLine("Completed success");
        }
    }
}

```