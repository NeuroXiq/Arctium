using Arctium.Protocol.DNS.Model;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS.Protocol
{
    public class DnsResolverImpl
    {
        private DnsResolverOptions options;
        private IDnsResolverCache cache { get { return options.Cache; } }

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

        internal async Task<IPAddress[]> ResolveHostNameToHostAddress(string hostName)
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

                await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);
                var sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint);

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

        ResourceRecord[] Step1_CheckLocalInformations(DnsResolverRequestState state)
        {

        }

        void Step2_FindBestServersToAsk(DnsResolverRequestState state)
        {

        }

        async Task Step3_SendQueriesUntilOneResponse(DnsResolverRequestState state)
        {
        
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
        internal async Task<ResourceRecord[]> ResolveHostNameToHostAddress2(string hostName)
        {
            DnsResolverRequestState state = new DnsResolverRequestState();

            // step 1
            if (!options.Cache.TryGet(state.SName, state.SType, state.SClass, out ResourceRecord[] records))
            {
                return records;
            }

            // step 2

            // first check NS rr for domain
            object[] nameServersToAsk = new object[0];
            string parentHostName = hostName;
            bool found = false;
            
            do
            {
                found = options.Cache.TryGet(parentHostName, QType.NS, state.SClass, out var nameServers);
                parentHostName = GetParentDomain(parentHostName);

            } while (!found && parentHostName != null);


            // step 3

            Message clientRequest = new Message();

            try
            {
                var response = SendQueryToServerAsync(clientRequest, dnsServerIp);

                // if response resolved ok or name error cache result
                if (response != null /* if response*/)
                {
                    cache.SetAnswer(hostName, response);

                    return response;
                }

                // if response delegation to other server:
                if (true)
                {
                    cache.SetDelegation(hostName, response);
                    goto step2;
                }

                // if response is CNAME and is not an answer
                if (true)
                {
                    cache.CacheCname(hostName, response);
                    // change sname to canonical name and go to step 1
                    goto step1;
                }

                // if server failure or bizzare content skip this server
                if (true)
                {
                    toSkip.Add(dnsServerIp);
                }
            }
            catch (Exception e)
            {
                // what if no internet connection?

                toSkip.Add(dnsServerIp);
            }

            throw new NotImplementedException();
        }

        private IPAddress FindBestServersToAsk(string hostName, IList<IPAddress> ignoreServers)
        {
            if (options.Cache.TryGetDelegation(hostName, out var ipAddress))
            {
                return ipAddress;
            }

            var fromOptions = options.DnsServers?.FirstOrDefault(x => !ignoreServers.Any(toSkip => toSkip.Equals(x)));

            if (fromOptions != null)
            {
                return fromOptions;
            }

            var fromRootServers = DnsRootServers.All.FirstOrDefault(x => !ignoreServers.Any(toSkip => toSkip.Equals(x)))?.IPv4Address;

            if (fromRootServers != null)
            {
                return fromRootServers;
            }

            throw new DnsException(DnsProtocolError.CannotFindDnsServerToAsk, "Cannot find DNS server to ask");
        }
    }
}
