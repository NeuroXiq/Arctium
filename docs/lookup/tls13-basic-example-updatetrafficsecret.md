```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Key Update
 * Example demonstrates how to update traffic secret to next generation key on client and server side
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
            Task.Factory.StartNew(StartServer);
            Thread.Sleep(1000); // wait for server start
            Task.Factory.StartNew(StartClient);

            Thread.Sleep(100000000);
        }

        static void StartServer()
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
                    byte[] received = new byte[256];
                        
                    tlsStream.Write(Encoding.ASCII.GetBytes("Hello from server before key update"));
                    int count = tlsStream.Read(received);
                    Console.WriteLine("Server received before key update: " + Encoding.ASCII.GetString(received, 0, count));

                    // updating traffic secret
                    // true -> request update from other party
                    // false -> do not request update from other party
                    // can be called any time any number of times
                    tlsStream.PostHandshakeKeyUpdate(true);
                    tlsStream.PostHandshakeKeyUpdate(false);
                    tlsStream.PostHandshakeKeyUpdate(false);

                    count = tlsStream.Read(received);
                    tlsStream.Write(Encoding.ASCII.GetBytes("Hello from server after key update"));

                    Console.WriteLine("Server received after key update: " + Encoding.ASCII.GetString(received, 0, count));

                }
                catch (Exception e)
                {
                    Console.WriteLine("Error");
                }
            }
        }

        static void StartClient()
        {
            var clientContext = Tls13ClientContext.DefaultUnsafe();
            var client = new Tls13Client(clientContext);
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(new IPEndPoint(IPAddress.Loopback, 444));

            var networkstream = new NetworkStream(socket);
            var tlsstream = client.Connect(networkstream);
            byte[] read = new byte[1024];

            tlsstream.Write(Encoding.ASCII.GetBytes("Hello from client before key update"));
            int count = tlsstream.Read(read);

            Console.WriteLine("ClientReceived: " + Encoding.ASCII.GetString(read, 0, count));

            // Example update on client side
            // update traffic secret, any number of time at any time
            tlsstream.PostHandshakeKeyUpdate(false);
            tlsstream.PostHandshakeKeyUpdate(false);
            tlsstream.PostHandshakeKeyUpdate(false);

            tlsstream.Write(Encoding.ASCII.GetBytes("Hello from client after key update"));
            count = tlsstream.Read(read);

            Console.WriteLine("Client Received: " + Encoding.ASCII.GetString(read, 0, count));
        }
    }
}

```