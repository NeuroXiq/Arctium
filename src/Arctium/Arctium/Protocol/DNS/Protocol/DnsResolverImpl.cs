using Arctium.Protocol.DNS.Model;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

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

        public async Task<ResourceRecord[]> QueryServerAsStubResolver(IPAddress serverIp, string hostName, QType qtype, bool skipCache = false)
        {
            Message clientMessage, serverMessage;
            ResourceRecord[] records;

            if (skipCache || !TryResolveFromCache(hostName, QClass.IN, qtype, out records))
            {
                clientMessage = CreateMessage(hostName, QClass.IN, qtype, true);
                serverMessage = await SendMessage(clientMessage, serverIp);

                if (serverMessage.Header.RCode == ResponseCode.NoErrorCondition)
                {
                    options.Cache.Set(serverMessage.Answer);

                    // resolve cname alias
                    string cname = hostName;
                    ResourceRecord r = null;
                    
                    for (int i = 0; i < serverMessage.Answer.Length; i++)
                    {
                        r = serverMessage.Answer
                            .Where(t => t.IsNameTypeClassEqual(cname, QClass.IN, QType.CNAME))
                            .FirstOrDefault();

                        if (r != null) cname = r.AsRData<RDataCNAME>().CName;
                    }

                    if (r != null) throw new DnsException("cyclic cname");

                    records = serverMessage.Answer
                        .Where(t => t.IsNameTypeClassEqual(cname, QClass.IN, qtype))
                        .ToArray();
                }
                else throw new DnsException($"ResponseCode is '{serverMessage.Header.RCode}'");
            }

            return records;
        }

        private async Task<Message> SendMessage(
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
                using var timeout = new CancellationTokenSource(options.UdpSocketRecvTimeoutMs);

                using (Socket socket = new Socket(ipAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);
                    sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint, timeout.Token);
                }

                result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));
                serverMessage = result;

                if (serverMessage.Header.Id != clientMessage.Header.Id)
                    throw new DnsException(DnsProtocolError.ClientError, "server header id reply does not match client header ID");
            }

            if (serverMessage == null || (replyTcpWhenTruncated && serverMessage?.Header.TC == true))
            {
                using var timeout = new CancellationTokenSource(options.UdpSocketRecvTimeoutMs);

                throw new NotImplementedException();

                serverMessage = null; //todo
            }

            if (serverMessage.Header.Id != clientMessage.Header.Id)
                throw new DnsException(DnsProtocolError.ClientError, "server header id reply does not match client header ID");

            return serverMessage;
        }

        Message CreateMessage(string hostName, QClass qclass, QType qtype, bool rd)
        {
            Header header = new Header
            {
                Id = (ushort)Random.Shared.NextInt64(),
                AA = false,
                RA = false,
                RD = options.RecursionDesired,
                TC = false,
                Opcode = Opcode.Query,
                ANCount = 0,
                ARCount = 0,
                NSCount = 0,
                QDCount = 1,
                QR = QRType.Query,
                RCode = ResponseCode.NoErrorCondition,
            };

            Question question = new Question
            {
                QClass = qclass,
                QType = qtype,
                QName = hostName,
            };

            Message message = new Message
            {
                Header = header,
                Question = new Question[] { question },
                Additional = null,
                Answer = null,
                Authority = null
            };

            return message;
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

        public async Task<ResourceRecord[]> QueryServerAsFullResolver(string sname, QClass qclass, QType qtype)
        {
            RequestState state = new RequestState(options.Cache);

            return await QueryServerAsFullResolver(sname, qclass, qtype, state);
        }

        private bool TryResolveFromCache(
            string hostName,
            QClass qclass,
            QType qtype,
            out ResourceRecord[] result,
            IDnsResolverCache requiredCache = null)
        {
            ResourceRecord[] records;
            HashSet<string> processedCnames = new HashSet<string>();
            bool isCname;
            
            do
            {
                processedCnames.Add(hostName);

                isCname = (requiredCache != null && requiredCache.TryGet(hostName, qclass, QType.CNAME, out records))
                    || options.Cache.TryGet(hostName, qclass, QType.CNAME, out records);

                if (isCname)
                {
                    if (qtype == QType.CNAME)
                    {
                        result = records;
                        return true;
                    }

                    hostName = records[0].AsRData<RDataCNAME>().CName;

                    if (processedCnames.Contains(hostName))
                        throw new DnsException("cache processing shows cyclic cname " + hostName);
                }
            } while (isCname);

            if ((requiredCache != null && requiredCache.TryGet(hostName, qclass, qtype, out result))
                    || options.Cache.TryGet(hostName, qclass, qtype, out result))
            {
                return true;
            }
            else
            {
                result = null;
                return false;
            }
        }

        private bool TryResolveIpsFromCache(string hostName, QClass qclass, out IPAddress[] outIps, IDnsResolverCache requiredCache)
        {
            List<IPAddress> ips = new List<IPAddress>();

            if (TryResolveFromCache(hostName, qclass, QType.A, out var ip4, requiredCache))
            {
                ips.AddRange(ip4.Select(ConvertToIPAddress));
            }

            if (TryResolveFromCache(hostName, qclass, QType.AAAA, out var ip6, requiredCache))
            {
                ips.AddRange(ip6.Select(ConvertToIPAddress));
            }

            if (ips.Count > 0)
            {
                outIps = ips.ToArray();
                return true;
            }
            else
            {
                outIps = null;
                return false;
            }
        }

        // RFC-1035 5.3.3. Algorithm
        // todo max recursrion level
        private async Task<ResourceRecord[]> QueryServerAsFullResolver(string sname, QClass qclass, QType qtype, RequestState state)
        {
            string serverToAskHostName;
            ResourceRecord[] resultRecords, sbelt, exactAnswer;
            IPAddress[] serverToAskIps;
            Queue<string> nsToAsk = new Queue<string>();
            Message clientMessage, response = null;
            bool cacheResponse = true, isInfiniteLoop = false, isDelegation, innerBreak;
            string searchingDomain;
            List<ResourceRecord> best;

            do
            {
                innerBreak = false;
                nsToAsk.Clear();

                // step 1
                if (TryResolveFromCache(sname,qclass, qtype, out resultRecords, state.ProcessingRequiredCache))
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
                    if (TryResolveFromCache(searchingDomain, qclass, QType.NS, out ResourceRecord[] cachedNs, state.ProcessingRequiredCache))
                    {
                        best.AddRange(cachedNs);
                    }

                    searchingDomain = GetParentDomain(searchingDomain);
                } while (searchingDomain != null);

                sbelt = options.SBeltServers;
                best.AddRange(sbelt.Where(t => t.Type == QType.NS));
                state.Set(sbelt);

                // sorting is very important,
                // first must be servers that are nearest to searching domain,
                // means servers with record.Name that is the longest suffix of searching domain must be first
                // in the queue
                best = best
                    .Distinct()
                    .OrderByDescending(t => sname.EndsWith(t.Name, StringComparison.OrdinalIgnoreCase) ? t.Name.Length : 0)
                    .ThenByDescending(t => t.Name.Length)
                    .ThenByDescending(t => {
                        // order if already have ip (have ip first)

                        string hostName = t.Type == QType.CNAME
                            ? t.AsRData<RDataCNAME>().CName
                            : t.AsRData<RDataNS>().NSDName;

                        return TryResolveIpsFromCache(hostName, qclass, out var ips, state.ProcessingRequiredCache) ? 1 : 0;
                        })
                    .ToList();

                foreach (var nsOrCname in best)
                {
                    string hostName = nsOrCname.Type == QType.NS
                        ? nsOrCname.AsRData<RDataNS>().NSDName
                        : nsOrCname.AsRData<RDataCNAME>().CName;
                    
                    nsToAsk.Enqueue(hostName);
                }

                // step 3 try to send queries to all server until one responds
                do
                {
                    if (nsToAsk.Count == 0)
                    {
                        throw new DnsException("failed to resolve - no more servers to ask (all asked servers failed)");
                    }

                    serverToAskHostName = nsToAsk.Dequeue();
                    // e.g. sname = 'ns1.server.com', servertoask='ns1.server.com', asking for 'A/AAAA' records
                    // need IP address of 'ns1.server.com' so need to query 'ns1.server.com' for ip then
                    // need IP address of 'ns1.server.com' so need to query 'ns1.server.com' for ip etc.
                    // skip this server
                    isInfiniteLoop = DnsHelper.DnsNameEquals(serverToAskHostName, sname);

                    if (!TryResolveIpsFromCache(serverToAskHostName, qclass, out serverToAskIps, state.RealCache) && !isInfiniteLoop)
                    {
                        try
                        {
                            ResourceRecord[] serverIp4 = await QueryServerAsFullResolver(serverToAskHostName, qclass, QType.A, state);
                            ResourceRecord[] serverIp6 = await QueryServerAsFullResolver(serverToAskHostName, qclass, QType.AAAA, state);

                            serverToAskIps = serverIp4.Union(serverIp6).Select(ConvertToIPAddress).ToArray();
                        }
                        catch
                        {
                            serverToAskIps = null;
                        }
                    }

                    // cache (or resolved value) may be empty - this is ok because maybe there are no A/AAAA records
                    // and domain name is valid, skip this server
                    if (serverToAskIps == null || serverToAskIps.Length == 0) continue;

                    // query server
                    // if server has multiple IP addresses, try until first give response
                    foreach (var nsIpAddress in serverToAskIps)
                    {
                        try
                        {
                            state.RequestCounter++;

                            if (state.RequestCounter >= options.MaxRequestCountForResolve)
                            {
                                throw new DnsException("error, maximum number of requests, operation cancelled");
                            }

                            clientMessage = CreateMessage(sname, qclass, qtype, options.RecursionDesired);
                            response = await SendMessage(clientMessage, nsIpAddress);

                            if (response != null) break;
                        }
                        catch { }
                    }

                    // step 4
                    // investigate server response

                    if (response == null) continue;

                    isDelegation = response.Authority.Any(t => t.Type == QType.NS);
                    exactAnswer = response.Answer
                            .Where(t => t.IsNameTypeClassEqual(sname, qclass, qtype))
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

        public static IPAddress ConvertToIPAddress(ResourceRecord record)
        {
            if (record.Type == QType.A)
            {
                uint ip = record.AsRData<RDataA>().Address;

                return new IPAddress(
                    ((ip & 0xff000000) >> 24) |
                    ((ip & 0x00ff0000) >> 8) |
                    ((ip & 0x0000ff00) << 8) |
                    ((ip & 0x000000ff) << 24)
                    );
            }
            else if (record.Type == QType.AAAA)
            {
                return new IPAddress(record.AsRData<RDataAAAA>().IPv6);
            }
            else
            {
                throw new ArgumentException($"record is not A or AAAA, current type: {record.Type} ({record.GetType().Name})");
            }
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

            public void Set(ResourceRecord[] records)
            {
                ProcessingRequiredCache.Set(records);
                RealCache.Set(records);
            }
        }
    }
}