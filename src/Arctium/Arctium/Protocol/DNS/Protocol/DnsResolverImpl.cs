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

        void Step2_FindBestServersToAsk(DnsResolverRequestState state)
        {

        }

        async Task<Message> TrySendMessageToServer(string sname, QClass qclass, QType qtype, IPAddress serverAddress)
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
                QClass = qclass,
                QType = qtype,
                QName = sname,
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
        // todo max recursrion level
        internal async Task<ResourceRecord[]> QueryServerForData(string sname, QClass qclass, QType qtype)
        {
            RDataNS serverToAsk;
            List<ResourceRecord> nsToAsk;
            List<ResourceRecord> serverToAskAddresses;
            // must force to cache some of the records during processing even if LocalData.Cache not caching them
            List<ResourceRecord> requiredTempCache;
            List<ResourceRecord> sbelt;
            IPAddress nsIPAddress;
            Message response = null;
            bool sbeltUsed = false;
            int requestCounter = 0;

            // step 1
            // check if already in cache
            if (options.LocalData.TryGetCache(sname, qclass, qtype, out ResourceRecord[] records))
            {
                // done, found in cache
                // return records;
            }

            requiredTempCache = new List<ResourceRecord>();
            nsToAsk = new List<ResourceRecord>();

            // step 2
            // check cache, parent, parent-parent ns
            //if (!options.LocalData.TryGetCache(parentHostName, qclass, QType.NS, out var nameServers))
            //{
            //    nameServers = await QueryServerForData(GetParentDomain(parentHostName), qclass, QType.NS);
            //}

            // step 3
            // send queries until one responds
            do
            {
                if (nsToAsk.Count == 0 && !sbeltUsed)
                {
                    sbelt = options.LocalData.SBeltServers.ToList();
                    nsToAsk = sbelt.Where(t => t.Type == QType.NS).ToList();
                    requiredTempCache.AddRange(sbelt);
                    sbeltUsed = true;

                    continue;
                }

                serverToAsk = nsToAsk.First().GetRData<RDataNS>();
                nsToAsk.RemoveAt(0);
                serverToAskAddresses = requiredTempCache.Where(t =>
                    string.Compare(t.Name, serverToAsk.NSDName, true) == 0
                    && t.Class == qclass
                    && (t.Type == QType.A || t.Type == QType.AAAA))
                    .ToList();

                if (serverToAskAddresses.Count == 0)
                {
                    continue;
                }

                foreach (var nsAddress in serverToAskAddresses)
                {
                    try
                    {
                        nsIPAddress = nsAddress.Type == QType.A
                            ? IPAddress.Parse(DnsSerialize.UIntToIpv4(nsAddress.GetRData<RDataA>().Address))
                            : new IPAddress(nsAddress.GetRData<RDataAAAA>().IPv6);

                        requestCounter++;
                        response = await TrySendMessageToServer(sname, qclass, qtype, nsIPAddress);

                        if (response != null) break;
                    }
                    catch
                    {
                        continue;
                    }
                }

                // step 4
                // investigate response

                // validate
                if (response.Answer.Any(t => t.Class != qclass || t.Type != qtype))
                {
                    continue;
                }

                options.LocalData.AddCache(response.Answer);
                options.LocalData.AddCache(response.Authority);
                options.LocalData.AddCache(response.Additional);
                requiredTempCache.AddRange(response.Answer);
                requiredTempCache.AddRange(response.Authority);
                requiredTempCache.AddRange(response.Additional);

                bool hasDelegation = response.Authority.Any(t => t.Type == QType.NS);

                // 4.a answers question?
                if (response.Header.RCode == ResponseCode.NoErrorCondition && response.Answer.Length > 0)
                {
                    return response.Answer;
                }
                // 4.a no records?
                else if (response.Header.RCode == ResponseCode.NoErrorCondition && response.Answer.Length == 0 && !hasDelegation)
                {
                    return new ResourceRecord[0];
                }
                // 4.a name error?
                else if (response.Header.RCode == ResponseCode.NameError)
                {
                    // todo cache data
                    throw new DnsException("Cannot resolve host name. Host name does not exists");
                }
                // 4.b better delegation?
                else if (hasDelegation)
                {
                    foreach (ResourceRecord nsRecord in response.Authority)
                        nsToAsk.Insert(0, nsRecord);
                }
                // 4.c response shows CNAME?
                else if (response.Answer.Length == 1 && response.Answer[0].Type == QType.CNAME && qtype != QType.CNAME)
                {
                    sname = response.Answer[0].GetRData<RDataCNAME>().CName;

                    if (options.LocalData.TryGetCache(sname, qclass, qtype, out ResourceRecord[] cachedCname))
                    {
                        return cachedCname;
                    }
                }
                // (custom arctium behaviour)
                else if (requestCounter >= options.MaxRequestCountForResolve)
                {
                    throw new DnsException("Maximum number of requests exceeded, resolve operation cancelled");
                }
                // 4.d response shows server failure or other bizzare content
                else
                {
                    // continue with other servers
                }
            } while (true);
        }
    }
}