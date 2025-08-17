using Arctium.Protocol.DNSImpl.Protocol;
using Arctium.Shared.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsException : ArctiumException
    {
        public DnsDecodeError? DecodeError { get; set; }
        public DnsProtocolError? ProtocolError { get; set; }

        public DnsException(string msg) : base(msg) { }
        public DnsException(DnsDecodeError code) : base($"Decode error: {code.ToString()} ({(int)code})") { }
        public DnsException(DnsProtocolError code) : base($"Protocol error: {code.ToString()} ({(int)code})") { }
    }
}
