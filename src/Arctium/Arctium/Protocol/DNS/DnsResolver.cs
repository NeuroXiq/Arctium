using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS
{
    public class DnsResolver
    {
        private DnsResolverOptions options;
        private DnsResolverImpl dnsResolverImpl;

        public DnsResolver() : this (DnsResolverOptions.CreateDefault()) { }

        public DnsResolver(DnsResolverOptions options)
        {
            this.options = options;
            dnsResolverImpl = new DnsResolverImpl(options);
        }

        public async Task<IPAddress[]> ResolveHostNameToHostAddress(string hostName)
        {
            DnsResolverImpl.RequestState state = new DnsResolverImpl.RequestState(options.LocalData.Cache);

            ResourceRecord[] ipv4Result = await dnsResolverImpl.QueryServerForData(hostName, QClass.IN, QType.A, state);
            ResourceRecord[] ipv6Result = await dnsResolverImpl.QueryServerForData(hostName, QClass.IN, QType.AAAA, state);

            IPAddress[] ipv4Address = ipv4Result.Select(t => IPAddress.Parse(DnsSerialize.UIntToIpv4(t.AsRData<RDataA>().Address)))
                .ToArray();

            IPAddress[] ipv6Address = ipv6Result.Select(t => t.AsRData<RDataAAAA>().IPv6)
                .Select(ipv6ByteArray => new IPAddress(ipv6ByteArray))
                .ToArray();

            IPAddress[] result = ipv4Address.Concat(ipv6Address).ToArray();

            return result;
        }

        public string ResolveHostAddressToHostName(IPAddress ipAddress)
        {
            dnsResolverImpl.ResolveHostAddressToHostName(ipAddress);

            return null;
        }

        public object ResolveGeneralLookupFunction(string hostName, QType qtype, QClass qclass)
        {
            throw new NotImplementedException();
            //return dnsResolverImpl.ResolveGeneralLookupFunction(hostName, qtype, qclass);
        }

        public static async Task<Message> SendDnsTcpMessageAsync(Message message, IPAddress ipAddress, int port = DnsConsts.DefaultServerDnsPort)
        {
            DnsSerialize serialize = new DnsSerialize();
            ByteBuffer messageBuffer = new ByteBuffer(), recvBuffer = new ByteBuffer();
            Socket clientSocket;
            Message result;
            int recvLength = 0, shouldRecvLength = 2, recv = 0;
            byte[] tempRecvBuffer = new byte[256];

            serialize.Encode(message, messageBuffer, true);

            using (clientSocket = new Socket(ipAddress.AddressFamily,SocketType.Stream, ProtocolType.Tcp))
            {
                await clientSocket.ConnectAsync(new IPEndPoint(ipAddress, port));
                await clientSocket.SendAsync(new ArraySegment<byte>(messageBuffer.Buffer, 0, messageBuffer.Length));

                do
                {
                    recv = await clientSocket.ReceiveAsync(tempRecvBuffer);
                    recvLength += recv;

                    if (recv == 0)
                    {
                        throw new DnsException(DnsProtocolError.ReceivedZeroBytesButExpectedMoreTcp, "received 0 bytes from tcp connection");
                    }

                    recvBuffer.Append(tempRecvBuffer, 0, recvLength);

                    if (recvLength >= 2 && shouldRecvLength == 2)
                    {
                        shouldRecvLength = 2 + MemMap.ToUShort2BytesBE(tempRecvBuffer, 0);

                        if (shouldRecvLength == 2) break;
                    }
                } while (recvLength < shouldRecvLength);
            }

            result = serialize.Decode(new BytesCursor(recvBuffer.Buffer, 0, recvLength), true);

            return result;
        }

        /// <summary>
        /// Opens socket, sends arbitrary <see cref="Message"/> to the server, and returns response
        /// Returns raw response message without any futher processing 
        /// (e.g. will no cache, no recurse, no resolve CNAME, no do redirects etc.)
        /// </summary>
        /// <param name="message">Message to send</param>
        /// <returns>Result message from DNS server</returns>
        public static async Task<Message> SendDnsUdpMessageAsync(Message message, IPAddress ipAddress, int port = DnsConsts.DefaultServerDnsPort)
        {
            DnsSerialize serialize = new DnsSerialize();
            ByteBuffer bbuf = new ByteBuffer();
            byte[] receiveBuffer = new byte[DnsConsts.UdpSizeLimit];

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint endpoint = new IPEndPoint(ipAddress, port);
            serialize.Encode(message, bbuf);

            
            {
                // todo
                throw new NotSupportedException();
            }
            
            await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);
            var sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint);

            Message result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));
            // Message result = serialize.Decode(new BytesCursor(a, 0, a.Length));

            return result;
        }
    }
}
