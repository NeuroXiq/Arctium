using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl.Model
{
    internal struct InitialPacket
    {
        const byte MaskReservedBits = 0x0C;
        const byte MaskPacketNumberLength = 0x3;

        /*
         * Header Form (1) = 1,
         * Fixed Bit (1) = 1,
         * Long Packet Type (2) = 0,
         * Reserved Bits (2),
         * Packet Number Length (2
         */

        public bool HeaderForm { get { return (FirstByte & LongHeaderPacket.MaskFixedBit) != 0; } }
        public bool FixedBit { get { return (FirstByte & LongHeaderPacket.MaskFixedBit) != 0; } }
        public LongPacketType LongPacketType { get { return LongHeaderPacket.GetLongPacketType(FirstByte); } }
        public byte ReservedBits { get { return (byte)((FirstByte & MaskReservedBits) >> 2); } }
        public int PacketNumberLength { get { return (FirstByte & MaskPacketNumberLength) >> 0; } }

        public byte FirstByte;
        public uint Version;
        public byte DestConnIdLen;
        public Memory<byte> DestConId;
        public byte SrcConIdLen;
        public Memory<byte> SrcConId;
        public ulong TokenLen;
        public Memory<byte> Token;
        public ulong Length;
        public uint PacketNumber;
        public Memory<byte> Payload;
    }
}
