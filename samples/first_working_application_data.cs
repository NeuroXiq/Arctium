using Arctium.Connection.Tls;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IgnoreConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            OpenSocketStream();
            
        }


        static void OpenSocketStream()
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            s.Bind(new IPEndPoint(IPAddress.Any, 1234));
            s.Listen(123);
            while (true)
            {

                

               // while(true)
                {
                    var client = s.Accept();
                    Task.Factory.StartNew(() =>
                    {
                        try
                        {

                        


                        TlsConnection tlsConnection = new TlsConnection(new NetworkStream(client));

                        TlsStream tlsStream = tlsConnection.Accept();


                        while (true)
                        {
                            byte[] buffer = new byte[12345];
                            tlsStream.Read(buffer, 0, 12345);

                            string a = Encoding.ASCII.GetString(buffer);
                            string path = a.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)[0].Split(' ')[1];

                            if (path == "/") path = "D:/VINCA_TEST_WEBSITE/index.html";
                            else path = "D:/VINCA_TEST_WEBSITE" + path;


                            if (!File.Exists(path))
                            {
                                string nf = "HTTP/1.1 404 notfound\r\n" +
                                "Host: localhost\r\n" +
                                //"Content-type: text/html\r\n" +
                                "Content-length: 0\r\n\r\n";

                                byte[] httpResponsenf = Encoding.ASCII.GetBytes(nf);

                                tlsStream.Write(httpResponsenf, 0, httpResponsenf.Length);
                                //tlsStream.Write(httpResponse, 0, httpResponse.Length);

                                continue;
                            }


                            FileStream fs = new FileStream(path, FileMode.Open);
                            int size = (int)new FileInfo(path).Length;
                            byte[] siteBytes = new byte[size];
                            int length = fs.Read(siteBytes, 0, siteBytes.Length);

                            string toWrite = "HTTP/1.1 200 OK\r\n" +
                                "Host: localhost\r\n" +
                                //"Content-type: text/html\r\n" +
                                "Content-length: " + length.ToString() + "\r\n\r\n";

                            byte[] httpResponse = Encoding.ASCII.GetBytes(toWrite);

                            tlsStream.Write(httpResponse, 0, httpResponse.Length);
                            tlsStream.Write(siteBytes, 0, length);

                            fs.Close();
                        }
                    }
                        catch (Exception)
                        {

                            
                        }
                    });

                    //it works !
                    //Console.ReadLine();asdasd
                //catch (Exception)
                {
                    //client.Close();
                    
                }
                

            }
            
        }
    }
}
