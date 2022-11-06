```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 -ALPN
 * Example demonstrates how to configure ALPN on server side.
 * Note that configuration is an new class that must inherit from base abstract class
 * When I ran this code and connected using 'cURL' then I had following output:
 *
 * [OUTPUT]
 * > Received Standarized name:
 * > Protocol Name: HTTP_2_over_TLS
 * > Received Standarized name:
 * > Protocol Name: HTTP_1_1
 * > Server connection info result:
 * > http/1.1
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;

namespace ConsoleAppTest
{
    //
    // This is configuration of ALPN on server size.
    // Configuration must inherit from base class
    // 'Handle' method must return one of result:
    //  - selected protocol index = negotiation success
    //  - alert fatal = negotiation fail with alert fatal
    //  - ignore = negotiation fail but do not abort and continue, alpn is ignored
    //

    class ServerALPN : ExtensionServerConfigALPN
    {
        public override Result Handle(byte[][] protocolNameListFromClient, ResultSelect resultSelector)
        {
            // See what client sent:
            //
            foreach (var protocolName in protocolNameListFromClient)
            {
                ALPNProtocol? standarizedName;

                if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(protocolName, out standarizedName))
                {
                    Console.WriteLine("Received Standarized name: ");
                    Console.WriteLine("Protocol Name: {0}", standarizedName.Value.ToString());
                }
                else
                {
                    Console.WriteLine("Received Not Standarized name (Can be converted to from bytes to string if needed)");
                }
            }


            // now select supported ALPN protocol: 
            // In this example HTTP/1.1 is negotiated
            // If not HTTP 1 present then ignoring

            for (int i = 0; i < protocolNameListFromClient.Length; i++)
            {
                byte[] protocolName = protocolNameListFromClient[i];
                ALPNProtocol? standarizedName;
                
                if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(protocolName, out standarizedName))
                {
                    if (standarizedName.Value == ALPNProtocol.HTTP_1_1)
                    {
                        // return index of selected protocol
                        return resultSelector.Success(i);
                    }
                }
            }

            // ok client did not sent http/1.1
            // so ignoring this extension

            return resultSelector.NotSelectedIgnore();

            // but also can abort connection

            return resultSelector.NotSelectedFatalAlert();
        }
    }

    internal class MainProgram
    {
        static Socket socket;

        static void Main()
        {
            socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 444));
            socket.Listen(20);

            StartServer();
        }

        static void StartServer()
        {
            var certificateWithPrivateKey = Tls13Resources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1;
            var serverContext = Tls13ServerContext.Default(new[] { certificateWithPrivateKey });


            /* Configuration for ALPN on server using custom class */
            serverContext.Config.ConfigueExtensionALPN(new ServerALPN());

            var tlsServer = new Tls13Server(serverContext);
            var networkStream = AcceptSocketNetworkStream();
            var tlsStream = tlsServer.Accept(networkStream, out var connectionInfo);

            // Result of ALPN on server can be found in connectionInfo

            Console.WriteLine("Server connection info result: ");
            Console.WriteLine(Encoding.ASCII.GetString(connectionInfo.ExtensionResultALPN.Protocol));

            // read from stream, do something etc. ...
            // tlsstream.read(...)
        }

        static NetworkStream AcceptSocketNetworkStream()
        {
            var rawSocket = socket.Accept();
            return new NetworkStream(rawSocket);
        }
    }
}

```