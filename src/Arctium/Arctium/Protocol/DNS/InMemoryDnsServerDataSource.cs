using Arctium.Protocol.DNSImpl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDnsServerDataSource : IDnsServerDataSource
    {
        List<InMemRRData> records;

        public InMemoryDnsServerDataSource()
        {
            records = new List<InMemRRData>();
        }

        public Task<ResourceRecord[]> GetRRsAsync(Question question)
        {
            string searchingDomainName = question.QName.TrimEnd('.');

            ResourceRecord[] results =
                records.Where(t =>
                t.QName?.TrimEnd('.') == searchingDomainName &&
                (t.Record.Class == question.QClass || question.QClass == QClass.AnyClass) &&
                (t.Record.Type == question.QType || question.QType == QType.All))
                .Select(t => t.Record)
                .ToArray();

            return Task.FromResult(results);
        }

        public void Add(InMemRRData record) => records.Add(record);

        public void AddRange(List<InMemRRData> records)
        {
            foreach (var record in records)
            {
                Add(record);
            }
        }
    }

    public class InMemRRData
    {
        public ResourceRecord Record;
        public string QName;

        public InMemRRData(string qname, QClass qclass, QType qtype, string name, int ttl, object rdata)
        {
            Record = new ResourceRecord()
            {
                Class = qclass,
                Name = name,
                RData = rdata,
                RDLength = 0,
                TTL = ttl,
                Type = qtype
            };

            QName = qname;
        }
    }
}
