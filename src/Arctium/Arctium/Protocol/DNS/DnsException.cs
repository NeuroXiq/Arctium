using Arctium.Protocol.DNSImpl.Protocol;
using Arctium.Shared.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    internal class DnsException : ArctiumException
    {
        public DnsException(string msg) : base(msg) { }
        public DnsException(DnsProtocolError errorCode) : base($"Decode error: {errorCode.ToString()} ({(int)errorCode})") { }
    }
}
