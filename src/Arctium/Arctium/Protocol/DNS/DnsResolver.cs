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

        /// <summary>
        /// Stub resolver, use specific server, send message with 'recursion desired' flag 
        /// and return response
        /// </summary>
        /// <returns></returns>
        public async Task<IPAddress[]> ResolveHostNameToAddressAsStubAsync(IPAddress serverIp, string hostName)
        {
            var recordsIp4 = await dnsResolverImpl.QueryServerAsStubResolver(serverIp, hostName, QType.A);
            var recordsIp6 = await dnsResolverImpl.QueryServerAsStubResolver(serverIp, hostName, QType.AAAA);
            var result = recordsIp4
                .Union(recordsIp6)
                .Select(DnsSerialize.ConvertToIPAddress)
                .ToArray();

            return result;
        }

        public async Task<IPAddress[]> ResolveHostNameToHostAddressAsync(string hostName)
        {
            ResourceRecord[] ipv4Result = await dnsResolverImpl.QueryServerAsFullResolver(hostName, QClass.IN, QType.A);
            ResourceRecord[] ipv6Result = await dnsResolverImpl.QueryServerAsFullResolver(hostName, QClass.IN, QType.AAAA);

            IPAddress[] result = ipv4Result
                .Union(ipv6Result)
                .Select(DnsSerialize.ConvertToIPAddress)
                .ToArray();

            return result;
        }

        public string ResolveHostAddressToHostName(IPAddress ipAddress)
        {
            dnsResolverImpl.ResolveHostAddressToHostName(ipAddress);
            throw new NotImplementedException();
            return null;
        }

        public Task<ResourceRecord[]> ResolveGeneralLookupFunctionAsync(string hostName, QType qtype, QClass qclass)
        {
            return dnsResolverImpl.QueryServerAsFullResolver(hostName, qclass, qtype);
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
            
            await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);
            var sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint);

            Message result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));

            return result;
        }
    }
}
