using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl.Model
{
    internal class LongHeaderPacket
    {
        // Header Form(1) = 1,
        // Fixed Bit(1) = 1,
        // Long Packet Type(2),
        // Type-Specific Bits(4)
        public byte HF_FB_LPT_TSB;
        public uint Version;
        public byte DestinationConnectionIdLength;
        public byte[] DestinationConnectionId;
        public byte SourceConnectionIdLength;
        public byte[] SourceConnectionId;
        public byte[] TypeSpecificPayload;
    }
}
