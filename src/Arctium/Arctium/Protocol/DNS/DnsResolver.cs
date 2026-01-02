using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS
{
    public class DnsResolver
    {
        private DnsResolverOptions options;
        private DnsResolverImpl dnsResolverImpl;
        
        /// <summary>
        /// Initialize new instance with default options
        /// </summary>
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
                .Select(DnsResolverImpl.ConvertToIPAddress)
                .ToArray();

            return result;
        }

        public async Task<IPAddress[]> ResolveHostNameToHostAddressAsync(string hostName)
        {
            ResourceRecord[] ipv4Result = await dnsResolverImpl.QueryServerAsFullResolver(hostName, QClass.IN, QType.A);
            ResourceRecord[] ipv6Result = await dnsResolverImpl.QueryServerAsFullResolver(hostName, QClass.IN, QType.AAAA);

            IPAddress[] result = ipv4Result
                .Union(ipv6Result)
                .Select(DnsResolverImpl.ConvertToIPAddress)
                .ToArray();

            return result;
        }

        public string ResolveHostAddressToHostNameAsync(IPAddress dnsServerIp, IPAddress hostToResolveIp)
        {
            if (dnsServerIp == null) throw new ArgumentNullException("dnsServerIp");
            if (hostToResolveIp == null) throw new ArgumentNullException("hostToResolveIp");

            throw new NotImplementedException();
            // return ResolveInverseQueryAsync(dnsServerIp, null);
        }

        public async Task<string> ResolvePtrReverseResolution(IPAddress dnsServerIp, IPAddress ipAddress)
        {
            string hostName;
            byte[] i;
            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                i = ipAddress.GetAddressBytes();
                hostName = string.Format("{0}.{1}.{2}.{3}.IN-ADDR.ARPA", i[3], i[2], i[1], i[0]);
            }
            else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                i = ipAddress.GetAddressBytes();
                // reversed as nibbles
                hostName = string.Format("" +
                    "{0:X}.{1:X}.{2:X}.{3:X}.{4:X}.{5:X}.{6:X}.{7:X}.{8:X}." + 
                    "{9:X}.{10:X}.{11:X}.{12:X}.{13:X}.{14:X}.{15:X}.{16:X}." + 
                    "{17:X}.{18:X}.{19:X}.{20:X}.{21:X}.{22:X}.{23:X}.{24:X}." + 
                    "{25:X}.{26:X}.{27:X}.{28:X}.{29:X}.{30:X}.{31:X}.ip6.arpa",
                    (i[15] & 0x0F), ((i[15] >> 4) & 0x0F),
                    (i[14] & 0x0F), ((i[14] >> 4) & 0x0F),
                    (i[13] & 0x0F), ((i[13] >> 4) & 0x0F),
                    (i[12] & 0x0F), ((i[12] >> 4) & 0x0F),
                    (i[11] & 0x0F), ((i[11] >> 4) & 0x0F),
                    (i[10] & 0x0F), ((i[10] >> 4) & 0x0F),
                    (i[09] & 0x0F), ((i[09] >> 4) & 0x0F),
                    (i[08] & 0x0F), ((i[08] >> 4) & 0x0F),
                    (i[07] & 0x0F), ((i[07] >> 4) & 0x0F),
                    (i[06] & 0x0F), ((i[06] >> 4) & 0x0F),
                    (i[05] & 0x0F), ((i[05] >> 4) & 0x0F),
                    (i[04] & 0x0F), ((i[04] >> 4) & 0x0F),
                    (i[03] & 0x0F), ((i[03] >> 4) & 0x0F),
                    (i[02] & 0x0F), ((i[02] >> 4) & 0x0F),
                    (i[01] & 0x0F), ((i[01] >> 4) & 0x0F),
                    (i[00] & 0x0F), ((i[00] >> 4) & 0x0F));

            }
            else throw new ArgumentException("ipAddress is not ip4 or ip6");

            var result = await ResolveGeneralLookupFunctionAsync(hostName, QClass.IN, QType.PTR).ConfigureAwait(false);

            if (result != null && result.Length > 0 && result[0].Type == QType.PTR)
            {
                return result[0].AsRData<RDataPTR>().PtrDName;
            }
            else throw new DnsException("failed to resolve reverse-dns name");
        }

        public Task<ResourceRecord[]> ResolveGeneralLookupFunctionAsync(string hostName, QClass qclass, QType qtype)
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
