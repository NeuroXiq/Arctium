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

                using var socket = new Socket(ipAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
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
            string result;
            int nextDot;

            if (domainName == string.Empty) return null;

            nextDot = domainName.IndexOf('.');

            if (nextDot < 1) return string.Empty;

            result = domainName.Substring(nextDot + 1);

            return result;
        }

        class RequestState
        {
            public int RequestCounter;
            // must force to cache some of the records during processing even if LocalData.Cache not caching them
            public TempProxyCache TempCache;
        }

        // RFC-1035 5.3.3. Algorithm
        // todo max recursrion level
        internal async Task<ResourceRecord[]> QueryServerForData(string sname, QClass qclass, QType qtype, RequestState state)
        {
            RDataNS serverToAsk;
            Queue<ResourceRecord> nsToAsk;
            List<ResourceRecord> serverToAskAddresses, sbelt;
            TempProxyCache requiredTempCache = state.TempCache;
            IPAddress nsIPAddress;
            ResourceRecord[] resultRecords = null;
            Message response = null;
            bool isDelegation;
            bool cacheResponse = true;
            bool innerBreak = false;

            innerBreak = false;
            nsToAsk = new Queue<ResourceRecord>();

            // step 1
            // check if already in cache
            if (options.LocalData.TryGetCache(sname, qclass, qtype, out resultRecords))
            {
                // done, found in cache
                return resultRecords;
            }

            // step 2
            // find best servers to ask
            string searchingDomain = sname;
            var best = new List<ResourceRecord>();

            do
            {
                best.AddRange(requiredTempCache.Where(rr => rr.Type == QType.NS && rr.Class == qclass && rr.Name == searchingDomain));
                if (options.LocalData.TryGetCache(searchingDomain, qclass, QType.NS, out ResourceRecord[] cachedNs))
                    best.AddRange(cachedNs);

                searchingDomain = GetParentDomain(searchingDomain);
            } while (searchingDomain != null);

            // best 5 - sbelt
            sbelt = options.LocalData.SBeltServers.ToList();
            best.AddRange(sbelt.Where(t => t.Type == QType.NS));
            requiredTempCache.AddRange(sbelt);

            // best servers:
            // ResourceRecord.Name longest (best match with sname),
            // already cached IP Address (no need to resolve name server IP)
            best = best
                .DistinctBy(t => t.GetRData<RDataNS>().NSDName)
                .OrderByDescending(t => sname.EndsWith(t.Name) ? t.Name.Length : -1)
                .OrderByDescending(t => requiredTempCache.Count(t => t.Class == qclass && t.Type == QType.AAAA && t.Type == QType.A))
                .ToList();

            best.ForEach(nsToAsk.Enqueue);

            // step 3 send them queries until one responds
            do
            {
                if (nsToAsk.Count == 0)
                {
                    throw new DnsException("failed to resolve - no more servers to ask (all asked servers failed)");
                }

                if (state.RequestCounter >= options.MaxRequestCountForResolve)
                {
                    throw new DnsException("Maximum number of requests exceeded, resolve operation cancelled");
                }

                serverToAsk = nsToAsk.Dequeue().GetRData<RDataNS>();

                serverToAskAddresses = requiredTempCache
                    .Where(t =>
                        string.Compare(t.Name, serverToAsk.NSDName, true) == 0
                        && t.Class == qclass
                        && (t.Type == QType.A || t.Type == QType.AAAA))
                    .ToList();

                if (serverToAskAddresses.Count == 0)
                {
                    serverToAskAddresses = (await QueryServerForData(serverToAsk.NSDName, qclass, QType.A)).ToList();
                }

                if (serverToAskAddresses.Count == 0) continue;

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
                // investigate server response

                isDelegation = response.Authority.Any(t => t.Type == QType.NS);
                var exactAnswer = response.Answer
                        .Where(t => t.Type == qtype && t.Class == qclass)
                        .ToArray();

                cacheResponse = true;
                resultRecords = null;
                bool answerQuestion = exactAnswer.Length > 0;
                answerQuestion |= !isDelegation && response.Answer.Length == 0;
                answerQuestion &= response.Header.RCode == ResponseCode.NoErrorCondition;

                // 4.a answers question?
                if (answerQuestion)
                {
                    resultRecords = exactAnswer;
                }
                // 4.a name error?
                else if (response.Header.RCode == ResponseCode.NameError)
                {
                    // todo cache data
                    throw new DnsException("Cannot resolve host name. Host name does not exists");
                }
                // 4.b better delegation?
                else if (isDelegation)
                {
                    innerBreak = true;
                }
                // 4.c response shows CNAME?
                else if (response.Answer.Count(t => t.Type == QType.CNAME) == 1)
                {
                    return await QueryServerForData(response.Answer.Single(t => t.Type == QType.CNAME).GetRData<RDataCNAME>().CName, qclass, qtype);
                }
                // 4.d response shows server failure or other bizzare content
                else
                {
                    // continue with other servers
                    cacheResponse = false;
                }

                if (cacheResponse)
                {
                    options.LocalData.AddCache(response.Answer);
                    options.LocalData.AddCache(response.Authority);
                    options.LocalData.AddCache(response.Additional);
                    requiredTempCache.AddRange(response.Answer);
                    requiredTempCache.AddRange(response.Additional);
                    requiredTempCache.AddRange(response.Authority);
                }

                if (resultRecords != null) return resultRecords;

            } while (!innerBreak);
        }
    }
}