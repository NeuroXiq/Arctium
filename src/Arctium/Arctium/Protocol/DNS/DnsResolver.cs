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
            DnsResolverImpl.RequestState state = new DnsResolverImpl.RequestState(this.options.LocalData.Cache);

            ResourceRecord[] ipv4Result = await dnsResolverImpl.QueryServerForData(hostName, QClass.IN, QType.A, state);
            ResourceRecord[] ipv6Result = await dnsResolverImpl.QueryServerForData(hostName, QClass.IN, QType.AAAA, state);

            IPAddress[] ipv4Address = ipv4Result.Select(t => IPAddress.Parse(DnsSerialize.UIntToIpv4(t.GetRData<RDataA>().Address)))
                .ToArray();

            IPAddress[] ipv6Address = ipv6Result.Select(t => t.GetRData<RDataAAAA>().IPv6)
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

        public async Task<Message> SendDnsTcpMessageAsync(Message message, IPAddress ipAddress, int port = DnsConsts.DefaultServerDnsPort)
        {
            throw new NotImplementedException();
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
            
            if (bbuf.Length > DnsConsts.UdpSizeLimit)
            {
                // todo
                throw new NotSupportedException();
            }

            serialize.Encode(message, bbuf);
            await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);
            var sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint);

            Message result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));
            // Message result = serialize.Decode(new BytesCursor(a, 0, a.Length));

            return result;
        }
    }
}
