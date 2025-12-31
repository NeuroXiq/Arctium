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

        private async Task<Message> SendQueryToServerAsync(
            Message clientMessage,
            IPAddress ipAddress,
            bool replyTcpWhenTruncated = true)
        {
            byte[] receiveBuffer;
            SocketReceiveFromResult sresult;
            IPEndPoint endpoint = null;
            Message serverMessage = null, result;
            DnsSerialize serialize = new DnsSerialize();
            ByteBuffer bbuf = new ByteBuffer();

            serialize.Encode(clientMessage, bbuf);

            if (bbuf.Length <= DnsConsts.UdpSizeLimit)
            {
                receiveBuffer = new byte[DnsConsts.UdpSizeLimit];
                endpoint = new IPEndPoint(ipAddress, DnsConsts.DefaultServerDnsPort);

                using (Socket socket = new Socket(ipAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);
                    sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint);
                }

                result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));
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

        // RFC-1035 5.3.3. Algorithm
        // todo max recursrion level
        internal async Task<ResourceRecord[]> QueryServerForData(string sname, QClass qclass, QType qtype, RequestState state)
        {
            RDataNS serverToAsk;
            ResourceRecord[] resultRecords, serverToAskAddresses, sbelt, exactAnswer, addresses;
            IPAddress nsIPAddress;
            Queue<ResourceRecord> nsToAsk = new Queue<ResourceRecord>();
            Message response = null;
            bool cacheResponse = true, isInfiniteLoop = false, isDelegation, innerBreak;
            string searchingDomain, cnameCacheResolved;
            List<ResourceRecord> best;

            do
            {
                innerBreak = false;
                nsToAsk.Clear();

                // step 1
                // check for CNAME
                // try to resolve cname
                cnameCacheResolved = sname;
                if (qtype != QType.CNAME)
                {
                    while (state.TryGet(cnameCacheResolved, qclass, QType.CNAME, out resultRecords))
                    {
                        if (resultRecords.Length == 1)
                            cnameCacheResolved = resultRecords[0].AsRData<RDataCNAME>().CName;
                        else break;
                    }
                }

                // check if already in cache
                if (state.TryGet(cnameCacheResolved, qclass, qtype, out resultRecords))
                {
                    // done, found in cache
                    return resultRecords;
                }

                // step 2
                // find best servers to ask
                // best servers to ask:
                // * server is authority/has info about of domain, or parent domain or parent-parent domain etc.
                // * largest 'record.Name' length (best match with sname)
                // * already cached IP Address
                // * sbelt as last resort

                searchingDomain = sname;
                best = new List<ResourceRecord>();

                do
                {
                    if (state.TryGet(searchingDomain, qclass, QType.NS, out ResourceRecord[] cachedNs))
                        best.AddRange(cachedNs);

                    searchingDomain = GetParentDomain(searchingDomain);
                } while (searchingDomain != null);

                sbelt = options.SBeltServers;
                best.AddRange(sbelt.Where(t => t.Type == QType.NS));
                state.Set(sbelt);

                best = best
                    .DistinctBy(t => t.AsRData<RDataNS>().NSDName)
                    .OrderByDescending(t => t.Name.Length)
                    .OrderByDescending(t => (state.TryGetAandAAAA(t.Name, qclass, out addresses) && addresses.Length > 0) ? 1 : 0)
                    .ToList();

                best.ForEach(nsToAsk.Enqueue);

                // step 3 try to send queries to all server until one responds
                do
                {
                    if (nsToAsk.Count == 0)
                    {
                        throw new DnsException("failed to resolve - no more servers to ask (all asked servers failed)");
                    }

                    serverToAsk = nsToAsk.Dequeue().AsRData<RDataNS>();

                    // e.g. sname = 'ns1.server.com', servertoask='ns1.server.com', asking for 'A/AAAA' records
                    // need IP address of 'ns1.server.com' so need to query 'ns1.server.com' for ip then
                    // need IP address of 'ns1.server.com' so need to query 'ns1.server.com' for ip etc.
                    // skip this server
                    isInfiniteLoop = serverToAsk.NSDName == sname;

                    if (!state.TryGetAandAAAA(serverToAsk.NSDName, qclass, out serverToAskAddresses) && !isInfiniteLoop)
                    {
                        serverToAskAddresses = await QueryServerForData(serverToAsk.NSDName, qclass, QType.A, state);
                    }

                    // cache (or resolved value) may be empty - this is ok because maybe there are no A/AAAA records
                    // and domain name is valid, skip this server
                    if (serverToAskAddresses.Length == 0) continue;

                    // query server
                    // if server has multiple IP addresses, try until first give response
                    foreach (var nsAddress in serverToAskAddresses)
                    {
                        try
                        {
                            nsIPAddress = nsAddress.Type == QType.A
                                ? IPAddress.Parse(DnsSerialize.UIntToIpv4(nsAddress.AsRData<RDataA>().Address))
                                : new IPAddress(nsAddress.AsRData<RDataAAAA>().IPv6);

                            state.RequestCounter++;

                            if (state.RequestCounter >= options.MaxRequestCountForResolve)
                            {
                                throw new DnsException("error, maximum number of requests, operation cancelled");
                            }

                            response = await TrySendMessageToServer(sname, qclass, qtype, nsIPAddress);

                            if (response != null) break;
                        }
                        catch { }
                    }

                    // step 4
                    // investigate server response

                    isDelegation = response.Authority.Any(t => t.Type == QType.NS);
                    exactAnswer = response.Answer
                            .Where(t => t.Type == qtype && t.Class == qclass)
                            .ToArray();

                    cacheResponse = true;
                    resultRecords = null;

                    // 4.a answers question?
                    if (response.Header.RCode == ResponseCode.NoErrorCondition &&
                        (exactAnswer.Length > 0 || !isDelegation && response.Answer.Length == 0))
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
                        sname = response.Answer.Single(t => t.Type == QType.CNAME).AsRData<RDataCNAME>().CName;
                        innerBreak = true;
                    }
                    // 4.d response shows server failure or other bizzare content
                    else
                    {
                        // continue with other servers
                        cacheResponse = false;
                    }

                    if (cacheResponse)
                    {
                        state.Set(response.Answer);
                        state.Set(response.Authority);
                        state.Set(response.Additional);
                    }

                    if (resultRecords != null) return resultRecords;

                } while (!innerBreak);
            } while (true);
        }

        internal class RequestState
        {
            public int RequestCounter;
            // must force to cache some of the records because query processing 
            // requires caching some of the records
            public readonly InMemoryDnsResolverCache ProcessingRequiredCache;
            public readonly IDnsResolverCache RealCache;

            public RequestState(IDnsResolverCache realCache)
            {
                RequestCounter = 0;
                ProcessingRequiredCache = new InMemoryDnsResolverCache(true);
                RealCache = realCache;
            }

            public bool TryGet(string name, QClass qclass, QType qtype, out ResourceRecord[] records)
            {
                // always prefere required cache as it have newest data
                if (ProcessingRequiredCache.TryGet(name, qclass, qtype, out records))
                {
                    return true;
                }

                if (RealCache.TryGet(name, qclass, qtype, out records))
                {
                    return true;
                }

                return false;
            }

            public void Set(ResourceRecord[] records)
            {
                ProcessingRequiredCache.Set(records);
                RealCache.Set(records);
            }

            public bool TryGetAandAAAA(string name, QClass qclass, out ResourceRecord[] records)
            {
                List<ResourceRecord> result = new List<ResourceRecord>();
                ResourceRecord[] result1, result2;
                bool ok1, ok2;

                if (ok1 = TryGet(name, qclass, QType.A, out result1))
                    result.AddRange(result1);

                if (ok2 = TryGet(name, qclass, QType.AAAA, out result2))
                    result.AddRange(result2);

                if (ok1 || ok2)
                {
                    records = result.ToArray();
                    return true;
                }

                records = null;
                return false;
            }
        }
    }
}