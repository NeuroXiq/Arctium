using Arctium.Protocol.DNSImpl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public interface IDnsServerMasterFiles
    {
        Task<ResourceRecord[]> GetRRsAsync(Question question);
    }
}
