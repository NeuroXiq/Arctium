using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

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
            await dnsResolverImpl.ResolveHostNameToHostAddress(hostName);

            return null;
        }

        public string ResolveHostAddressToHostName(IPAddress ipAddress)
        {
            dnsResolverImpl.ResolveHostAddressToHostName(ipAddress);

            return null;
        }

        public object ResolveGeneralLookupFunction(string hostName, QType qtype, QClass qclass)
        {
            dnsResolverImpl.ResolveGeneralLookupFunction();

            return null;
        }

        /// <summary>
        /// Sends arbitrary <see cref="Message"/> to server. 
        /// Returns raw response message from server without
        /// any futher processing (e.g. will no cache, no recurse, no resolve CNAME, no do redirects etc.)
        /// </summary>
        /// <param name="message">Message to send</param>
        /// <returns>Result message from DNS server</returns>
        public static async Task<Message> SendDnsUdpMessageAsync(Message message, IPAddress ipAddress, int port = DnsConsts.DefaultServerUdpPort)
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

            // MemDump.HexDump(receiveBuffer, chunkLength: 1, chunksCountInLine: 16, delimiter:  ", ");

            // byte[] a = new byte[]
            // {
            //     0x04, 0xD2, 0x80, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
            //     0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
            //     0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x04, 0xD8, 0x3A, 0xD1, 0x04
            // };

            Message result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));
            // Message result = serialize.Decode(new BytesCursor(a, 0, a.Length));

            return result;
        }
    }
}
