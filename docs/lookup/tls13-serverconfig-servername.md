```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Server Name
 * Example demonstrates how to configure Server Name on server side
 *
 * [example output]
 * > Server name config - Received servername: localhost
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;

namespace ConsoleAppTest
{

    // This is a configuration of Server Name on server side
    // Not that it inherits from abstract class and must override
    // Handle method. Possible results are specified in example
    //
    class ConfigServerName : ExtensionServerConfigServerName
    {
        public override ResultAction Handle(byte[] hostName)
        {
            string hostNameString = Encoding.ASCII.GetString(hostName);
            Console.WriteLine("Server name config - Received servername: {0}", hostNameString);

            if (hostNameString == "localhost")
            {
                return ResultAction.Success;
            }
            else
            {
                return ResultAction.Ignore;
            }

            // also if needed can abort handshake with following return:

            return ResultAction.AbortFatalAlertUnrecognizedName;
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


            /* Configuration of Server Name */
            // create instance of custom config class
            serverContext.Config.ConfigureExtensionServerName(new ConfigServerName());

            var tlsServer = new Tls13Server(serverContext);
            var networkStream = AcceptSocketNetworkStream();
            var tlsStream = tlsServer.Accept(networkStream, out var connectionInfo);


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