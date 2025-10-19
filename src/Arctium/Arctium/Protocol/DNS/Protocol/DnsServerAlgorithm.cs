using Arctium.Protocol.DNS;
using Arctium.Protocol.DNS.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Protocol
{
    public class DnsServerAlgorithm : IDisposable
    {
        public List<ResourceRecord> outAnswer;
        public List<ResourceRecord> outAuthority;
        public List<ResourceRecord> outAdditional;
        public bool outRecursionAvailable;
        public bool outAuthoritativeAnswer;

        bool disposed;
        string qname;
        QClass qclass;
        QType qtype;
        DnsServerOptions options;
        Message clientMessage;
        IDnsServerRecordsData dataSource { get { return options.DnsServerDataSource; } }

        string name = null;
        string[] labels;
        int ancestorLvl = 0;
        string originalQname = null;

        public DnsServerAlgorithm(DnsServerOptions options, Message clientMsg)
        {
            disposed = false;
            outAnswer = new List<ResourceRecord>();
            outAuthority = new List<ResourceRecord>();
            outAdditional = new List<ResourceRecord>();

            qname = clientMsg.Question[0].QName;
            originalQname = clientMsg.Question[0].QName;
            qtype = clientMsg.Question[0].QType;
            qclass = clientMsg.Question[0].QClass;
            labels = qname.Split('.');
            this.options = options;
        }

        public void Dispose()
        {
            disposed = true;
        }

        public async Task Start()
        {
            if (disposed) throw new ObjectDisposedException(nameof(DnsServerAlgorithm));

            await Step1();

            Dispose();
        }

        async Task Step1()
        {
            if (options.RecursionAvailable && clientMessage.Header.RD)
            {
                await Step5();
            }
            else
            {
                await Step2();
            }
        }

        string QNameAncestor(int nodeAncestorLvl)
        {
            if (nodeAncestorLvl == labels.Length) return string.Empty;

            return string.Join('.', labels, nodeAncestorLvl, labels.Length - nodeAncestorLvl);
        }

        async Task Step2()
        {
            // 2. find zone that is nearest ancestor
            ResourceRecord soa = null;

            for (; ancestorLvl <= labels.Length; ancestorLvl++)
            {
                // in each iteration remove first label
                name = QNameAncestor(ancestorLvl);
                DnsNode node = await options.DnsServerDataSource.GetAsync(name, qclass, QType.SOA);

                if (node?.Records?.Count == 1)
                {
                    soa = node.Records[0];
                    break;
                }
                else if (node?.Records?.Count > 1)
                {
                    throw new DnsException(DnsProtocolError.Internal_MultipleDnsSOAZonesForSameDomain, $"dns name: {name}");
                }
            }

            if (soa != null)
            {
                await Step3();
            }
            else
            {
                await Step4();
            }
        }

        async Task Step3()
        {
            // 3. zone was found,
            // start match down label by label
            outAuthoritativeAnswer = true;
            DnsNode node = null;
            bool completed = false;

            for (; ancestorLvl >= 0 && !completed; ancestorLvl--)
            {
                name = QNameAncestor(ancestorLvl);
                node = await options.DnsServerDataSource.GetAsync(name, qclass, QType.All);

                // 3.a whole qname was found, we have valid node
                if (node != null && name.Length == qname.Length)
                {
                    var rr = node.Records.Where(t => t.Type == qtype).ToArray();

                    // data at node is cname and query is not cname
                    if (rr[0].Type == QType.CNAME && qtype != QType.CNAME)
                    {
                        // change qname to name from CNAME and search again
                        outAnswer.Add(rr[0]);
                        qname = ((RDataCNAME)rr[0].RData).CName;
                        await Step1();
                    }
                    else
                    {
                        outAnswer.AddRange(rr);
                        await Step6();
                    }

                    completed = true;
                }
                // 3.b, we have a referral
                else if (node != null && node.Records.Where(t => t.Type == QType.NS).Any())
                {
                    outAuthority.AddRange(node.Records.Where(a => a.Type == QType.NS));
                    await Step4();

                    return;
                }
                else if (node != null)
                {
                    // we have match and stil this is not final record
                    // continue search 
                    continue;
                }
                // 3.c if no match look if '*' exists
                else
                {
                    name = "*." + QNameAncestor(ancestorLvl - 1 >= 0 ? ancestorLvl - 1 : 0);
                    var sNode = await dataSource.GetAsync(name, qclass, QType.All);

                    // if label '*' exists, copy RRs and set '*' to QNAME
                    if (sNode != null)
                    {
                        IEnumerable<ResourceRecord> sRecords = sNode.Records
                            .Where(t => t.Type == qtype)
                            .Select(t => new ResourceRecord()
                            {
                                Class = t.Class,
                                // '*' to qname
                                Name = qname,
                                RData = t.RData,
                                RDLength = t.RDLength,
                                TTL = t.TTL,
                                Type = t.Type
                            });

                        outAnswer.AddRange(sRecords);

                        await Step6();

                        return;
                    }
                    else
                    {
                        // '*' does not exists, so no node with exists here or below

                        if (qname == originalQname)
                        {
                            // domain name not found and we are authoritative server
                            // therefore this domain must not exists everywhere.
                            // Return error response to client that domain name does not exists
                            throw new DnsException(DnsProtocolError.R3DomainNameDoesNotExists);
                        }
                        else
                        {
                            // just exit
                            return;
                        }
                    }
                }
            }
        }

        async Task Step4()
        {
            // start matching down in the cache
            outAuthoritativeAnswer = false;
            DnsNode node;

            if (options.DnsServerCacheDataSource == null &&
                (node = await options.DnsServerCacheDataSource.GetAsync(name, qclass, qtype)) != null)
            {
                outAnswer.AddRange(node.Records);

                // if there was no delegation from authoritative data
                // look for the best one from cache
                if (outAuthority.Count == 0)
                {
                    // todo does it works? SHOULD BE i <= labels.Length not '<' ?
                    for (int i = 0; i < labels.Length; i++)
                    {
                        // search up if any NS
                        var nodeName = QNameAncestor(i);
                        node = await options.DnsServerCacheDataSource.GetAsync(name, qclass, QType.NS);
                        outAuthority.AddRange(node.Records);
                    }
                }
            }

            await Step6();
        }

        async Task Step5()
        {
            // step 5
            var answer = await options.RecursionService.ResolveAsync(clientMessage);
            await Step6();
        }

        async Task Step6()
        {
            // attempt to add additional records

            var allRrs = outAnswer.Union(outAdditional);

            foreach (var record in allRrs)
            {
                if (record.Type == QType.MX)
                {
                    RDataMX mxRData = (RDataMX)record.RData;
                    IList<ResourceRecord> aForMx = (await options.DnsServerDataSource.GetAsync(mxRData.Exchange, qclass, QType.A))?.Records;
                    IList<ResourceRecord> aaaaForMx = (await options.DnsServerDataSource.GetAsync(mxRData.Exchange, qclass, QType.AAAA))?.Records;

                    if (aForMx != null) outAdditional.AddRange(aForMx);
                    if (aaaaForMx != null) outAdditional.AddRange(aaaaForMx);
                }

                if (record.Type == QType.NS)
                {
                    RDataNS nsRData = (RDataNS)record.RData;
                    IList<ResourceRecord> aForNs = (await options.DnsServerDataSource.GetAsync(nsRData.NSDName, qclass, QType.A))?.Records;
                    IList<ResourceRecord> aaaaForNs = (await options.DnsServerDataSource.GetAsync(nsRData.NSDName, qclass, QType.AAAA))?.Records;

                    if (aForNs != null) outAdditional.AddRange(aForNs);
                    if (aaaaForNs != null) outAdditional.AddRange(aaaaForNs);
                }
            }
        }
    }
}
