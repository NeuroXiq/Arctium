```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Basic example server
 * Example demonstrates how to show server TLS 1.3 established connection informations
 * 1. Run code
 * 2. Open webbrowser with 'https://www.localhost:444'
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

                    Console.WriteLine("{0}: {1}", nameof(serverConnectionInfo.ClientSupportPostHandshakeAuthentication), serverConnectionInfo.ClientSupportPostHandshakeAuthentication);
                    Console.WriteLine("{0}: {1}", nameof(serverConnectionInfo.IsPskSessionResumption), serverConnectionInfo.IsPskSessionResumption);
                    Console.WriteLine("{0}: {1}", nameof(serverConnectionInfo.CipherSuite), serverConnectionInfo.CipherSuite);
                    Console.WriteLine("{0}: {1}", nameof(serverConnectionInfo.ClientSupportPostHandshakeAuthentication), serverConnectionInfo.ClientSupportPostHandshakeAuthentication);

                }
                catch (Exception e)
                {
                    Console.WriteLine("Error");
                    Console.WriteLine(e.Message);
                }
            }
        }
    }
}

```