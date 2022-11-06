```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Basic example
 * Example demonstrates how to close TLS connection
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

                    Tls13ServerConnectionInfo serverConnectionInfo;
                    var tlsStream = tlsServer.Accept(networkStream, out serverConnectionInfo);

                    // close is exactly same for client & server
                    // invoke 'close' on Tls13Stream object
                    tlsServer.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error");
                }
            }
        }
    }
}

```