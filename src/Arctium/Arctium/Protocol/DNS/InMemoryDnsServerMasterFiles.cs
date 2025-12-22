using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDnsServerMasterFiles : IDnsServerRecordsData
    {
        public List<DnsNode> Nodes { get; set; }

        public InMemoryDnsServerMasterFiles()
        {
            Nodes = new List<DnsNode>();
        }

        /// <summary>
        /// Adds IN record type to the the list
        /// </summary>
        public void AddIN(string name, QType qtype, uint ttl, object rdata)
        {
            Add(name, QClass.IN, qtype, ttl, rdata);
        }

        public void Add(string name, QClass qclass, QType qtype, uint ttl, object rdata)
        {
            string[] labels = name.Split('.');
            DnsNode node;

            // create nodes if not exists
            for (int i = 0; i < labels.Length; i++)
            {
                string nodeName = string.Join('.', labels, labels.Length - i - 1, i + 1);
                node = Nodes.Where(t => t.Name == nodeName).FirstOrDefault();

                if (node == null)
                {
                    node = new DnsNode()
                    {
                        Label = labels[labels.Length - 1 - i],
                        Name = nodeName,
                        Records = new List<ResourceRecord>()
                    };

                    Nodes.Add(node);
                }
            }

            node = Nodes.Where(t => t.Name == name).Single();

            node.Records.Add(new ResourceRecord()
            {
                Class = qclass,
                Name = name,
                RData = rdata,
                TTL = ttl,
                Type = qtype,
                RDLength = 0
            });
        }

        public Task<DnsNode> GetAsync(string name, QClass qclass, QType qtype)
        {
            DnsNode node = Nodes.Where(t => string.Compare(t.Name, name, true) == 0).SingleOrDefault();
            List<ResourceRecord> records;

            if (node == null) return Task.FromResult<DnsNode>(null);

            if (qtype != QType.All)
            {
                records = node.Records.Where(t => t.Class == qclass && t.Type == qtype).ToList();
            }
            else
            {
                records = node.Records.Where(t => t.Class == qclass).ToList();
            }

            var result = new DnsNode()
            {
                Name = node.Name,
                Label = node.Label,
                Records = records
            };

            return Task.FromResult(result);
        }
    }
}
