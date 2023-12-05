using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1;
using Arctium.Standards.Connection.QUICv1Impl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicModelCoding
    {
        public QuicModelCoding() { }

        public static bool IsLongHeaderPacket(Span<byte> packet)
        {
            return (packet[0] & 0x80) > 0;
        }

        public static LongPacketType DecodeLHPType(Span<byte> data)
        {
            return (LongPacketType)(data[0] & 0x30);
        }

        internal static void DecodeLHPConnIds(byte[] readDgramBuf, out Memory<byte> srcId, out Memory<byte> destId)
        {
            // todo error max 20 bytes
            int destIdLen = readDgramBuf[5];
            int srcIdOffs = 5 + 1 + destIdLen;
            int srcIdLen = readDgramBuf[srcIdOffs];

            destId = new Memory<byte>(readDgramBuf, 6, destIdLen);
            srcId = new Memory<byte> (readDgramBuf, srcIdOffs, srcIdLen);
        }

        /// <summary>
        /// variable-length integer decoding
        /// </summary>
        public static ulong DecodeIntegerVLE(byte[] buffer, int offset, out int decodedBytesCount)
        {
            ulong result = 0;
            int type = (buffer[offset] & 0xC0) >> 6;
            decodedBytesCount = (1 << type);

            switch (type)
            {
                case 0: result = buffer[offset]; break;
                case 1: result = MemMap.ToUShort2BytesBE(buffer, offset); break;
                case 2: result = MemMap.ToUInt4BytesBE(buffer, offset); break;
                case 3: result = MemMap.ToULong8BytesBE(buffer, offset); break;
            }

            // first two bits - its a type from above, clear this not part of intege
            // clear two upper bits of current number
            int shift = (decodedBytesCount * 8) - 2;
            ulong clearFirstTwoBitsMask = ~((ulong)0x03 << shift);

            result &= clearFirstTwoBitsMask;

            return result;
        }

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

        public static int GetOffsetLHPPacketNumberField(byte[] buffer, int offset)
        {
            var buf = buffer;
            int o = offset;
            o += 1 + 4;
            o += buf[o] + 1; // dest connection id
            o += buf[o] + 1; // src connection id
            o += (int)DecodeIntegerVLE(buf, o, out int lenEncCount) + 1;

            return o;
        }

        public static LongHeaderPacket DecodeLHP(byte[] buffer, int offset, bool isEncrypted)
        {
            LongHeaderPacket p = new LongHeaderPacket();
            int o = offset;

            p.FirstByte = buffer[o];
            p.Version = MemMap.ToUInt4BytesBE(buffer, offset);
            QuicModelCoding.DecodeVerDestIDSrcID(buffer, offset, out p.Version, out p.DestConId, out p.SrcConId);
            o += 1 + 4 + 1 + p.DestConId.Length + 1 + p.SrcConId.Length;

            if (p.LongPacketType == LongPacketType.Initial)
            {
                p.TokenLen = DecodeIntegerVLE(buffer, o, out var tokenLenBytesCount);

                if (p.TokenLen > (128 * ushort.MaxValue))
                {
                    throw new QuicException("implementation error: max token len > 128 * ushort");
                }

                o += tokenLenBytesCount;
                p.Token = new Memory<byte>(buffer, o, (int)p.TokenLen);

                o += (int)p.TokenLen;

                p.Length = DecodeIntegerVLE(buffer, o, out var lengthEncCount);
                o += lengthEncCount;

                p.OffsetPacketNumber = o;

                if (!isEncrypted)
                {
                    switch (p.PacketNumberLength)
                    {
                        case 0: p.PacketNumber = buffer[o]; break;
                        case 1: p.PacketNumber = (uint)((buffer[o] << 8) | (buffer[o + 1] << 0)); break;
                        case 2: p.PacketNumber = (uint)((buffer[o] << 16) | (buffer[o + 1] << 8) | (buffer[o + 2] << 0)); break;
                        case 3: p.PacketNumber = MemMap.ToUInt4BytesBE(buffer, o); break;
                    }

                    o += p.PacketNumberLength + 1;
                    int payloadLen = ((int)p.Length - p.PacketNumberLength - 1);
                    p.Payload = new Memory<byte>(buffer, o, payloadLen);

                    p.HeaderLength = o - offset;
                }
            }
            else throw new NotImplementedException();
            
            

            return p;
        }

        public static InitialPacket DecodeInitialPacket(byte[] buffer, int offset)
        {
            InitialPacket p = new InitialPacket();
            int o = offset;

            p.FirstByte = buffer[o];
            p.Version = MemMap.ToUInt4BytesBE(buffer, offset);
            QuicModelCoding.DecodeVerDestIDSrcID(buffer, offset, out p.Version, out p.DestConId, out p.SrcConId);
            o += 1 + 4 + 1 + p.DestConId.Length + 1 + p.SrcConId.Length;
            p.TokenLen = DecodeIntegerVLE(buffer, o, out var tokenLenBytesCount);

            if (p.TokenLen > (128 * ushort.MaxValue))
            {
                throw new QuicException("implementation error: max token len > 128 * ushort");
            }

            o += tokenLenBytesCount;
            p.Token = new Memory<byte>(buffer, o, (int)p.TokenLen);

            o += (int)p.TokenLen;
            p.Length = DecodeIntegerVLE(buffer, o, out var lengthEncCount);
            o += lengthEncCount + 1;

            // todo this is encrypted
            switch (p.PacketNumberLength)
            {
                case 0: p.PacketNumber = buffer[o]; break;
                case 1: p.PacketNumber = (uint)((buffer[o] << 8) | (buffer[o + 1] << 0)); break;
                case 2: p.PacketNumber = (uint)((buffer[o] << 16) | (buffer[o + 1] << 8) | (buffer[o + 2] << 0)); break;
                case 3: p.PacketNumber = MemMap.ToUInt4BytesBE(buffer, o); break;
            }

            o += p.PacketNumberLength + 1;
            int payloadLen = ((int)p.Length - p.PacketNumberLength - 1);
            p.Payload = new Memory<byte>(buffer, o, payloadLen);

            return p;
        }
    }
}
