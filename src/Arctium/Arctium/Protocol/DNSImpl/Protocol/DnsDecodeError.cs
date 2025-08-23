using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    public enum DnsDecodeError : int
    {
        DecodeInvalidLabelLength = 1,
        DecodeMsgLengthNotMatchTotalLength = 2,
        TotalLengthOfDomainNameExceeded = 3,
    }
}
