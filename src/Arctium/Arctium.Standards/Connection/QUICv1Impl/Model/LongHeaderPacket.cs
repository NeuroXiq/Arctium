using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl.Model
{
    internal struct LongHeaderPacket
    {
        public const byte MaskHeaderForm = 0x80;
        public const byte MaskFixedBit = 0x40;
        public const byte MaskLongPacketType = 0x30;
        const byte MaskReservedBits = 0x0C;
        const byte MaskPacketNumberLength = 0x3;

        public static LongPacketType GetLongPacketType(byte firstByte) => (LongPacketType)((firstByte & MaskLongPacketType) >> 4);



        public bool HeaderForm { get { return (FirstByte & LongHeaderPacket.MaskFixedBit) != 0; } }
        public bool FixedBit { get { return (FirstByte & LongHeaderPacket.MaskFixedBit) != 0; } }
        public LongPacketType LongPacketType { get { return GetLongPacketType(FirstByte); } }
        public byte ReservedBits { get { return (byte)((FirstByte & MaskReservedBits) >> 2); } }
        public int PacketNumberLength { get { return (FirstByte & MaskPacketNumberLength) >> 0; } }

        public int OffsetPacketNumber;
        public int HeaderLength;

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
