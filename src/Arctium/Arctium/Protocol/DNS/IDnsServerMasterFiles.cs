using Arctium.Protocol.DNSImpl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public interface IDnsServerRecordsData
    {
        Task<ResourceRecord[]> GetRRsAsync(Question question);
        Task<ResourceRecord[]> Get(string name, QClass qclass, QType type);
    }
}
