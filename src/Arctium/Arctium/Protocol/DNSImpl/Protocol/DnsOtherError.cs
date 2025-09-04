using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    /// <summary>
    /// 
    /// </summary>
    public enum DnsOtherError : int
    {
        SerializeInvalidCharacterStringLength = 1,
        SerializeMaxRecordLengthExceeded = 2,
        SerializeInvalidIpv6LengthOrNull = 3,
    }
}
