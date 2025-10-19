using Arctium.Protocol.DNS.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public interface IDnsServerRecordsData
    {
        Task<DnsNode> GetAsync(string name, QClass qclass, QType type);
    }
}
