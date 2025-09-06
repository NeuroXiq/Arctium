using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    /// <summary>
    /// error related to specification of dns protocol and rfc
    /// format: <1-byte-rcode><1-byte-details>
    /// where:
    /// 1-byte-rcode: will return this rcode to client
    /// 1-byte-details: error details for internal purpose/debugging/logging details.
    /// </summary>
    public enum DnsProtocolError : int
    {
        // server: 0x01xx -> format error
        QRTypeNotQuery = 0x0101,
        QDCountNotEqual1 = 0x0102,
        DecodeInvalidLabelLength = 0x0103,
        DecodeMsgLengthNotMatchTotalLength = 0x0104,
        DecodeTotalLengthOfDomainNameExceeded = 0x0105,
        ReceivedZeroBytesButExpectedMoreTcp = 0x0107,
        DecodeMinHeaderLength = 0x0108,
        DecodeZValudNotZero = 0x109,

        // server: 0x02xx -> server failure (internal server error)
        EncodeInvalidCharacterStringLength = 0x0201,
        EncodeMaxRecordLengthExceeded = 0x0202,
        EncodeInvalidIpv6LengthOrNull = 0x0203,
        EncodeResponseMessageTcpExceedUShortMaxValue = 0x0204,
        EncodeMaxDomainNameLength = 0x205,
        EncodeInvalidLabel = 0x206,
        EncodeMaxCharStrLenght = 0x207,
        EncodeInvalidQType = 0x208,

        // server: 0x03xx -> name error (domain name does not exists, only from authoritative name server)

        // server: 0x04xx -> not implemented (name server not support this query type)

        // server: 0x05xx -> refused (name server refused perform this query)

    }
}
