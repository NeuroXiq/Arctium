using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl.Model
{
    internal class VersionNegotiationPacket
    {
        // Header Form (1), Ununsed(7)
        public byte HF_Unused;
        public uint Version;
        public byte DestConnectionIdLen;
        public byte[] DestConnectionId;
        public byte SrcConnectionIdLen;
        public byte[] SrcConnectionId;
    }
}
