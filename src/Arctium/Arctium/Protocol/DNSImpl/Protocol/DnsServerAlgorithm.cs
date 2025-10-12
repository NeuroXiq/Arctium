using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    public class DnsServerAlgorithm : IDisposable
    {
        public List<ResourceRecord> outAnswer;
        public List<ResourceRecord> outAuthority;
        public List<ResourceRecord> outAdditional;
        public bool outRecursionAvailable;

        bool disposed;
        string qname;
        QClass qclass;
        QType qtype;
        DnsServerOptions options;
        Message clientMessage;
        IDnsServerRecordsData recordsData { get { return options.DnsServerDataSource; } }

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
            return string.Join('.', labels, nodeAncestorLvl, labels.Length - nodeAncestorLvl) + ".";
        }

        async Task Step2()
        {
            // 2. find zone that is nearest ancestor
            ResourceRecord soa = null;

            for (; ancestorLvl < labels.Length; ancestorLvl++)
            {
                // in each iteration remove first label
                name = QNameAncestor(ancestorLvl);
                ResourceRecord[] records = await options.DnsServerDataSource.Get(name, qclass, QType.SOA);

                if (records?.Length > 0)
                {
                    if (records.Length > 1) throw new DnsException(DnsProtocolError.Internal_MultipleDnsSOAZonesForSameDomain, $"dns name: {name}");
                    soa = records[0];
                    break;
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
            ResourceRecord[] rr = null;
            for (; ancestorLvl >= 0; ancestorLvl--)
            {
                name = QNameAncestor(ancestorLvl);

                // 3.a whole qname was found, we have valid node
                if (name.Length == qname.Length)
                {
                    rr = await options.DnsServerDataSource.Get(name, qclass, qtype);

                    // data at node is cname and query is not cname
                    if (rr[0].Type == QType.CNAME && qtype != QType.CNAME)
                    {
                        // change qname to name from CNAME and search again
                        outAnswer.Add(rr[0]);
                        qname = ((RDataCNAME)rr[0].RData).CName;
                        await Step1();
                        return;
                    }
                    else
                    {
                        outAnswer.AddRange(rr);
                        await Step6();
                        return;
                    }
                }

                rr = await recordsData.Get(name, qclass, QType.NS);

                // 3.b, we have a referral
                if (rr.Length > 0)
                {
                    outAuthority.AddRange(rr.Where(a => a.Type == QType.NS));
                    await Step4();
                    return;
                }

                // 3.c if no match look if '*' exists
                name = "*." + QNameAncestor(ancestorLvl - 1 >= 0 ? ancestorLvl - 1 : 0);
                rr = await recordsData.Get(name, qclass, QType.All);

                // '*' does not exists
                if (rr.Length == 0)
                {
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
                else
                {
                    
                }
            }
        }

        async Task Step4()
        {
            // start matching down in the cache

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
                    ResourceRecord[] aForMx = await options.DnsServerDataSource.Get(mxRData.Exchange, qclass, QType.A);
                    ResourceRecord[] aaaaForMx = await options.DnsServerDataSource.Get(mxRData.Exchange, qclass, QType.AAAA);

                    if (aForMx != null) outAdditional.AddRange(aForMx);
                    if (aaaaForMx != null) outAdditional.AddRange(aaaaForMx);
                }

                if (record.Type == QType.NS)
                {
                    RDataNS nsRData = (RDataNS)record.RData;
                    ResourceRecord[] aForNs = await options.DnsServerDataSource.Get(nsRData.NSDName, qclass, QType.A);
                    ResourceRecord[] aaaaForNs = await options.DnsServerDataSource.Get(nsRData.NSDName, qclass, QType.AAAA);

                    if (aForNs != null) outAdditional.AddRange(aForNs);
                    if (aaaaForNs != null) outAdditional.AddRange(aaaaForNs);
                }
            }
        }
    }
}
