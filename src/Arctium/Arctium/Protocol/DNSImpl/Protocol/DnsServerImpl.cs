using Arctium.Protocol.DNS;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    public class DnsServerImpl
    {
        public DnsServerImpl(DnsServerOptions options)
        {
            
        }

        DnsSerialize serializer = new DnsSerialize();

        public void Start()
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var bindEndpoint = new IPEndPoint(IPAddress.Any, 53);


            s.Bind(bindEndpoint);

            byte[] buf = new byte[12345 ];


            while (true)
            {
                EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
                int recvLen = s.ReceiveFrom(buf, ref remoteEndpoint);
                var result = new BytesSpan(buf, 0, recvLen);

            }
        }

        async Task Process(BytesSpan packet)
        {
            
        }

        /*
         SocketAsyncEventArgs args = new SocketAsyncEventArgs();
            args.Completed += OnReceive;
            args.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);


            while (s.ReceiveFromAsync(args))
            {
                
            }
         */
    }
}
