```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Basic example server
 * Example demonstrates how to show client TLS 1.3 established connection informations
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

            // this object stores informations about connection
            Tls13ClientConnectionInfo clientConnectionInfo;
            var tlsStream = tlsClient.Connect(networkStream, out clientConnectionInfo);

            Console.WriteLine("{0}: {1}", nameof(clientConnectionInfo.CipherSuite), clientConnectionInfo.CipherSuite);
            Console.WriteLine("{0}: {1}", nameof(clientConnectionInfo.IsPskSessionResumption), clientConnectionInfo.IsPskSessionResumption);
            Console.WriteLine("{0}: {1}", nameof(clientConnectionInfo.ServerCertificates), clientConnectionInfo.ServerCertificates[0].Length);
            Console.WriteLine("{0}: {1}", nameof(clientConnectionInfo.ServerCertificateVerifySignatureScheme), clientConnectionInfo.ServerCertificateVerifySignatureScheme);
            Console.WriteLine("{0}: {1}", nameof(clientConnectionInfo.ServerRequestedCertificateInHandshake), clientConnectionInfo.ServerRequestedCertificateInHandshake);
            Console.WriteLine("{0}: {1}", nameof(clientConnectionInfo.KeyExchangeNamedGroup), clientConnectionInfo.KeyExchangeNamedGroup);

            /* [Example output]: 
             * 
             * CipherSuite: TLS_AES_128_GCM_SHA256
             * IsPskSessionResumption: False
             * ServerCertificates: 1390
             * ServerCertificateVerifySignatureScheme: EcdsaSecp256r1Sha256
             * ServerRequestedCertificateInHandshake: False
             * KeyExchangeNamedGroup: X25519
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