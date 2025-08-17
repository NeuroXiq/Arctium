using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    public enum DnsProtocolError : int
    {
        QRTypeNotQuery = 2,
        QDCountNotEqual1 = 3,
    }
}
