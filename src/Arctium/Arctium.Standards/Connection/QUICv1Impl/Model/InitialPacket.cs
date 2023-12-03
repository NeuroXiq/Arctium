using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl.Model
{
    internal class InitialPacket
    {
        /*
         * Header Form (1) = 1,
         * Fixed Bit (1) = 1,
         * Long Packet Type (2) = 0,
         * Reserved Bits (2),
         * Packet Number Length (2
         */
        public byte HF_FB_LPT_RB_PNL;
        public uint Version;
        public byte DestConnIdLen;
        public byte[] DestConnId;
        public byte SrcConnIdLen;
        public byte[] SrcCOnnId;
        public ulong TokenLen;
        public byte[] Token;
        public ushort PacketNumber;
        public byte[] Payload;
    }
}
