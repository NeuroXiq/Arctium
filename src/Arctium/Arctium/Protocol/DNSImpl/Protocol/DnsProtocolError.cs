using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    /// <summary>
    /// error related to specification of dns protocol and rfc
    /// </summary>
    public enum DnsProtocolError : int
    {
        QRTypeNotQuery = 1,
        QDCountNotEqual1 = 2,
        DecodeInvalidLabelLength = 3,
        DecodeMsgLengthNotMatchTotalLength = 4,
        TotalLengthOfDomainNameExceeded = 5,
        TxtMaxCharacterStringLength = 6,
        ReceivedZeroBytesFromClient = 7,
    }
}
