using Arctium.Protocol.DNS.Model;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;

namespace Arctium.Protocol.DNS.Protocol
{
    public class DnsResolverImpl
    {
        private DnsResolverOptions options;
        private IDndResolverLocalData localData { get { return options.LocalData; } }

        public DnsResolverImpl(DnsResolverOptions options)
        {
            this.options = options;
        }

        internal async Task SendDnsMessage(Message message)
        {
            return;
        }

        internal void ResolveGeneralLookupFunction(string hostName, QType qtype, QClass qclass)
        {
            throw new NotImplementedException();
        }

        internal void ResolveHostAddressToHostName(IPAddress ipAddress)
        {
            throw new NotImplementedException();
        }

        internal async Task<IPAddress[]> ResolveHostNameToHostAddress2(string hostName)
        {
            Header header = new Header()
            {
                Id = (ushort)Random.Shared.NextInt64(),
                AA = false,
                RA = false,
                RD = false,
                TC = false,
                Opcode = Opcode.Query,
                ANCount = 0,
                ARCount = 0,
                NSCount = 0,
                QDCount = 1,
                QR = QRType.Query,
                RCode = ResponseCode.NoErrorCondition,
            };

            Question question = new Question()
            {
                QClass = QClass.IN,
                QName = hostName,
                QType = QType.A
            };

            Message message = new Message()
            {
                Header = header,
                Question = new Question[] { question },
                Additional = null,
                Answer = null,
                Authority = null
            };

            Message ipv4Result = await SendQueryToServerAsync(message, IPAddress.Parse("8.8.8.8"));

            question.QType = QType.AAAA;

            Message ipv6Result = await SendQueryToServerAsync(message, IPAddress.Parse("8.8.8.8"));

            List<IPAddress> result = new List<IPAddress>();

            if (ipv4Result.Header.ANCount > 0)
            {
                IEnumerable<IPAddress> ipv4List = ipv4Result.Answer
                    .Where(a => a.Type == QType.A)
                    .Select(a => new IPAddress(a.GetRData<RDataA>().Address));

                result.AddRange(ipv4List);
            }

            if (ipv4Result.Header.ANCount > 0)
            {
                IEnumerable<IPAddress> ipv6List = ipv6Result.Answer
                    .Where(t => t.Type == QType.AAAA)
                    .Select(t => new IPAddress(t.GetRData<RDataAAAA>().IPv6));

                result.AddRange(ipv6List);
            }

            return result.ToArray();
        }

        private async Task<Message> SendQueryToServerAsync(
            Message clientMessage,
            IPAddress ipAddress,
            bool replyTcpWhenTruncated = true)
        {
            Message serverMessage = null;
            DnsSerialize serialize = new DnsSerialize();
            ByteBuffer bbuf = new ByteBuffer();
            serialize.Encode(clientMessage, bbuf);

            if (bbuf.Length <= DnsConsts.UdpSizeLimit)
            {
                byte[] receiveBuffer = new byte[DnsConsts.UdpSizeLimit];

                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                IPEndPoint endpoint = new IPEndPoint(ipAddress, DnsConsts.DefaultServerDnsPort);

                //await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);

//                receiveBuffer = new byte[]
//                {
//0x4F,0x17,0x80,0x00,0x00,0x01,0x00,0x00,0x00,0x0D,0x00,0x0C,0x03,0x77,0x77,0x77,
//0x06,0x67,0x6F,0x6F,0x67,0x6C,0x65,0x03,0x63,0x6F,0x6D,0x00,0x00,0x01,0x00,0x01,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x14,0x01,0x61,0x0C,0x67,
//0x74,0x6C,0x64,0x2D,0x73,0x65,0x72,0x76,0x65,0x72,0x73,0x03,0x6E,0x65,0x74,0x00,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x62,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x63,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x64,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x65,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x66,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x67,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x68,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x69,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6A,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6B,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6C,0xC0,0x2E,
//0xC0,0x17,0x00,0x02,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0x01,0x6D,0xC0,0x2E,
//0xC0,0x2C,0x00,0x01,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0xC0,0x05,0x06,0x1E,
//0xC0,0x2C,0x00,0x1C,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x10,0x20,0x01,0x05,0x03,
//0xA8,0x3E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x30,0xC0,0x4C,0x00,0x01,
//0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0xC0,0x21,0x0E,0x1E,0xC0,0x4C,0x00,0x1C,
//0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x10,0x20,0x01,0x05,0x03,0x23,0x1D,0x00,0x00,
//0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x30,0xC0,0x5C,0x00,0x01,0x00,0x01,0x00,0x02,
//0xA3,0x00,0x00,0x04,0xC0,0x1A,0x5C,0x1E,0xC0,0x5C,0x00,0x1C,0x00,0x01,0x00,0x02,
//0xA3,0x00,0x00,0x10,0x20,0x01,0x05,0x03,0x83,0xEB,0x00,0x00,0x00,0x00,0x00,0x00,
//0x00,0x00,0x00,0x30,0xC0,0x6C,0x00,0x01,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,
//0xC0,0x1F,0x50,0x1E,0xC0,0x6C,0x00,0x1C,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x10,
//0x20,0x01,0x05,0x00,0x85,0x6E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x30,
//0xC0,0x7C,0x00,0x01,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0xC0,0x0C,0x5E,0x1E,
//0xC0,0x7C,0x00,0x1C,0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x10,0x20,0x01,0x05,0x02,
//0x1C,0xA1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0xC0,0x8C,0x00,0x01,
//0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0xC0,0x23,0x33,0x1E,0xC0,0x9C,0x00,0x01,
//0x00,0x01,0x00,0x02,0xA3,0x00,0x00,0x04,0xC0,0x2A,0x5D,0x1E
//                };

                Message result2 = serialize.Decode(new BytesCursor(receiveBuffer, 0, receiveBuffer.Length));
                throw new Exception("test");

                var sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint);

#if DEBUG
                MemDump.HexDump(receiveBuffer, 0, sresult.ReceivedBytes, 16, 1, ",");
#endif

                Message result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));


                serverMessage = result;

                if (serverMessage.Header.Id != clientMessage.Header.Id)
                    throw new DnsException(DnsProtocolError.ClientError, "server header id reply does not match client header ID");
            }
            
            if (serverMessage == null || (replyTcpWhenTruncated && serverMessage?.Header.TC == true))
            {
                throw new NotImplementedException();

                serverMessage = null; //todo
            }

            if (serverMessage.Header.Id != clientMessage.Header.Id)
                throw new DnsException(DnsProtocolError.ClientError, "server header id reply does not match client header ID");

            return serverMessage;
        }

        void Step2_FindBestServersToAsk(DnsResolverRequestState state)
        {

        }

        async Task<Message> Step3_SendQueriesUntilOneResponse(DnsResolverRequestState state, IPAddress serverAddress)
        {
            try
            {
                Header header = new Header()
                {
                    Id = (ushort)Random.Shared.NextInt64(),
                    AA = false,
                    RA = false,
                    RD = false,
                    TC = false,
                    Opcode = Opcode.Query,
                    ANCount = 0,
                    ARCount = 0,
                    NSCount = 0,
                    QDCount = 1,
                    QR = QRType.Query,
                    RCode = ResponseCode.NoErrorCondition,
                };

                Question question = new Question()
                {
                    QClass = state.SClass,
                    QType = state.SType,
                    QName = state.SName,
                };

                Message message = new Message()
                {
                    Header = header,
                    Question = new Question[] { question },
                    Additional = null,
                    Answer = null,
                    Authority = null
                };

                Message serverResponse = await SendQueryToServerAsync(message, serverAddress);

                return serverResponse;
            }
            catch (Exception e)
            {

                throw;
            }
        }

        void Step4_AnalyzeResponse(DnsResolverRequestState state)
        {
            
        }

        string GetParentDomain(string domainName)
        {
            int nextDot = domainName.IndexOf('.');

            if (nextDot < 1) return null;

            string parentHostName = domainName.Substring(nextDot + 1);

            return parentHostName;
        }

        // RFC-1035 5.3.3. Algorithm 
        internal async Task<ResourceRecord[]> ResolveHostNameToHostAddress(string sname, QClass qclass, QType qtype)
        {
            sname = "www.google.com";
            //qtype = QType.NS;
            qtype = QType.A;
            DnsResolverRequestState state = new DnsResolverRequestState(sname, qclass, qtype);

            // step 1
            if (options.LocalData.TryGetCache(state.SName, state.SType, state.SClass, out ResourceRecord[] records))
            {
                return records;
            }

            // step 2

            // first check NS rr for domain
            IPAddress[] nameServersToAsk = new IPAddress[0];
            string parentHostName = sname;
            bool found = false;
            
            do
            {
                found = options.LocalData.TryGetCache(parentHostName, QType.NS, state.SClass, out var nameServers);
                parentHostName = GetParentDomain(parentHostName);

            } while (!found && parentHostName != null);

            if (nameServersToAsk == null) nameServersToAsk = new IPAddress[0];

            // step 3
            Message response = null;

            foreach (var nameServer in nameServersToAsk)
            {
                response = await Step3_SendQueriesUntilOneResponse(state, nameServer);

                if (response != null) break;
            }

            // no nameserver gived a response? try again with SBELT (last resort servers)
            if (response == null)
            {
                // IPAddress[] sbeltServers = localData.GetSBeltServers();
                IPAddress[] sbeltServers = new IPAddress[] { IPAddress.Parse("170.247.170.2") };

                foreach (var sbeltServer in sbeltServers)
                {
                    response = await Step3_SendQueriesUntilOneResponse(state, sbeltServer);

                    if (response != null) break;
                }
            }

            // if all servers failed then cannot do anything, operation failed
            if (response == null)
            {
                throw new DnsException("Queried all servers but and all servers failed to answer any correct DNS Message.");
            }

            // step 4 analyze response
            
            throw new NotImplementedException();
        }
    }
}
