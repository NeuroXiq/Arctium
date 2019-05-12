using Arctium.Connection.Tls;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IgnoreConsoleApp
{
    class Program
    {
        //
        // Example server connection over TLSv1.1 (only supported now)
        //
        // namespace for TLS support:
        // Arctium.Connection.Tls


        static void Main(string[] args)
        {
            ExampleTlsServer();
        }


        static void ExampleTlsServer()
        {

            //create classic socket
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverSocket.Bind(new IPEndPoint(IPAddress.Any, 443));
            serverSocket.Listen(123);

            //server certificate with RSA private and public key (MUST BE)
            X509Certificate2 cert = new X509Certificate2("D:\\test.pfx", "test", X509KeyStorageFlags.Exportable);

            //configure server connection (this is not server, this is 'tls connection on server side')
            //certifiate provided in ctor will be presented to all clients accepted on this instance
            TlsServerConnection tlsServerSide = new TlsServerConnection(cert);

            while (true)
            {
                Socket clientSocket = serverSocket.Accept();

                //
                //Create innerStream to inject into tls class
                Stream stream = new NetworkStream(clientSocket);

                //create tlsStream object based on specified innerStream
                TlsStream tlsStream = tlsServerSide.Accept(stream);

                //
                // Now state is after handshaked, can read and write data
                byte[] someRequest = new byte[0x1000];
                int readedBytes = tlsStream.Read(someRequest, 0, 0x1000);

                string readedString = Encoding.ASCII.GetString(someRequest, 0, readedBytes );
                Console.WriteLine(readedString);


                // in web browser type: https://localhost
                // Result:
                //
                // GET / HTTP / 1.1
                // Host: localhost
                // User - Agent: Mozilla / 5.0(Windows NT 6.3; Win64; x64; rv: 66.0) Gecko / 20100101 Firefox / 66.0
                // Accept: text / html,application / xhtml + xml,application / xml; q = 0.9,*/*;q=0.8
                // Accept-Language: en-US,en;q=0.5
                // Accept-Encoding: gzip, deflate, br
                // Connection: keep-alive
                // Upgrade-Insecure-Requests: 1
                //

                string exampleContentResponse =
                    "<head></head>" +
                    "<body> <p> Hello over Tls! </p> </body>";

                string exampleResponse =
                    "HTTP/1.1 200 OK\r\n" +
                    "Host: localhost\r\n" +
                    "Content-Length: " + exampleContentResponse.Length + "\r\n" +
                    "\r\n";

                byte[] httpHeaderBytes = Encoding.ASCII.GetBytes(exampleResponse);
                byte[] httpContentBytes = Encoding.ASCII.GetBytes(exampleContentResponse);

                tlsStream.Write(httpHeaderBytes, 0, httpHeaderBytes.Length);
                tlsStream.Write(httpContentBytes, 0, httpContentBytes.Length);

                Console.WriteLine("Received and sended success");
                Console.ReadLine();
            }
        }
    }
}
