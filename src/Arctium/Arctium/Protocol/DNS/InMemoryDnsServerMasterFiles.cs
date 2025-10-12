using Arctium.Protocol.DNSImpl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDnsServerMasterFiles : IDnsServerRecordsData
    {
        public List<ResourceRecord> Records { get; set; }

        public InMemoryDnsServerMasterFiles()
        {
            Records = new List<ResourceRecord>();
        }

        public Task<ResourceRecord[]> GetRRsAsync(Question question)
        {
            string searchingDomainName = question.QName.TrimEnd('.');

            ResourceRecord[] results =
                Records.Where(t =>
                t.Name?.TrimEnd('.') == searchingDomainName &&
                (t.Class == question.QClass || question.QClass == QClass.AnyClass) &&
                (t.Type == question.QType || question.QType == QType.All))
                .ToArray();

            return Task.FromResult(results);
        }

        /// <summary>
        /// Adds IN record type to the the list
        /// </summary>
        public void AddIN(string name, QType qtype, int ttl, object rdata)
        {
            Add(name, QClass.IN, qtype, ttl, rdata);
        }

        public void Add(string name, QClass qclass, QType qtype, int ttl, object rdata)
        {
            Records.Add(new ResourceRecord()
            {
                Class = qclass,
                Name = name,
                RData = rdata,
                TTL = ttl,
                Type = qtype,
                RDLength = 0
            });
        }
    }
}
