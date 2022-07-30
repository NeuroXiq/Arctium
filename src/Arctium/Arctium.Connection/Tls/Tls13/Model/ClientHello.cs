using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Connection.Tls.Tls13.Model
{
    internal class ClientHello
    {
        public ushort ProtocolVersion;
        public byte[] Random;
        public byte[] LegacySessionId;
        public byte[] CipherSuites;
        public byte[] LegacyCompressionMethods;
        public byte[] Extensions;
    }
}
