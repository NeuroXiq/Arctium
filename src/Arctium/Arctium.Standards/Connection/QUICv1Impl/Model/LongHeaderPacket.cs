using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl.Model
{
    internal class LongHeaderPacket
    {
        public const byte MaskHeaderForm = 0x80;
        public const byte MaskFixedBit = 0x40;
        public const byte MaskLongPacketType = 0x30;

        public static LongPacketType LongPacketType(byte firstByte) => (LongPacketType)((firstByte & MaskLongPacketType) >> 4);

        public static void DecodeVerDestIDSrcID(byte[] buffer, int offset, out uint ver, out Memory<byte> destId, out Memory<byte> srcId)
        {
            int o = offset;
            
            // version
            o += 1;
            ver = MemMap.ToUInt4BytesBE(buffer, o);

            // dest
            o += 4;
            int destLen = buffer[o];
            destId = new Memory<byte>(buffer, o + 1, destLen);

            // src 
            o += 1 + destLen;
            int srcLen = buffer[o];
            srcId = new Memory<byte>(buffer, o + 1, srcLen);
        }

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
