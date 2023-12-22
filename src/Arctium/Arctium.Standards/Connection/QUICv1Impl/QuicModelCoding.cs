using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1;
using Arctium.Standards.Connection.QUICv1Impl.Model;
using System;
using System.Collections.Generic;
using System.Data;
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

        #region Encoding

        public static void Encode_CryptoFrame(ByteBuffer output, CryptoFrame frame)
        {
            output.Append((byte)FrameType.Crypto);
            Encode_IntegerVLE(output, frame.Offset);
            Encode_IntegerVLE(output, frame.Length);
            output.Append(frame.Data.Span);
        }

        public static void Encode_ACKFrame(
            ByteBuffer output,
            AckFrame frame)
        {
            var type = frame.Type;
            var ecnCount = frame.EcnCounts;

            if (type != FrameType.Ack2 && type != FrameType.Ack3)
                throw new QuicException("internal: invalid ACK frametype");

            output.Append((byte)type);
            Encode_IntegerVLE(output, frame.LargestAcknowledged);
            Encode_IntegerVLE(output, frame.AckDelay);
            Encode_IntegerVLE(output, frame.AckRangeCount);
            Encode_IntegerVLE(output, frame.FirstAckRange);

            var ranges = frame.AckRange.Span;
            for (int i = 0; i < ranges.Length; i++)
            {
                var r = ranges[i];
                Encode_IntegerVLE(output, r.Gap);
                Encode_IntegerVLE(output, r.ACKRangeLength);
            }

            if (type == FrameType.Ack3)
            {
                var ec = frame.EcnCounts;
                Encode_IntegerVLE(output, ec.ECT0Count);
                Encode_IntegerVLE(output, ec.ECT1Count);
                Encode_IntegerVLE(output, ec.ECNCECount);
            }
        }

        public static int Encode_IntegerVLE_EncodeLength(ulong value)
        {
            if ((value & ((ulong)0x03 << 62)) != 0)
            {
                throw new QuicException("value too large to encode (invalid value)");
            }

            // rfc9000.pdf - 16. Variable-Length Integer Encoding 
            // first two MSB encode length in bytes, rest is integer,
            // this special values are in 'ifs' are just byte.max, ushort.max, int.max, ulong.max
            // without first two bits
            int enclen;

            if (value <= 63) enclen = 1;
            else if (value <= 16383) enclen = 2;
            else if (value <= 1073741823) enclen = 4;
            else enclen = 8;

            return enclen;
        }

        public static int Encode_IntegerVLE(ByteBuffer output, ulong value)
        {
            int enclen = Encode_IntegerVLE_EncodeLength(value);

            int o = output.MallocAppend(enclen);
            byte[] b = output.Buffer;

            switch (enclen)
            {
                case 1:
                    b[o] = (byte)value;
                    b[o] |= (byte)(0x00 << 6);
                    break;
                case 2:
                    MemMap.ToBytes1UShortBE((ushort)value, output.Buffer, o);
                    b[o] |= (byte)(0x01 << 6);
                    break;
                case 4:
                    MemMap.ToBytes1UIntBE((uint)value, output.Buffer, o);
                    b[o] |= (byte)(0x02 << 6);
                    break;
                case 8:
                    MemMap.ToBytes1ULongBE(value, output.Buffer, o);
                    b[o] |= (byte)(0x03 << 6);
                    break;
            }

            return enclen;
        }

        #endregion


        public static CryptoFrame DecodeFrame_Crypto(byte[] buf, int offset)
        {
            var f = new CryptoFrame();
            var b = buf;
            int o = offset;
            f.Type = (FrameType)b[o];
            o += 1;

            if (f.Type != FrameType.Crypto) throw new QuicException("implementatino: expected crypto frame");


            f.Offset = DecodeIntegerVLE(b, o, out int encoffs);
            o += encoffs;

            f.Length = DecodeIntegerVLE(b, o, out int enclen);
            o += enclen;

            f.Data = new Memory<byte>(buf, o, (int)f.Length);
            f.A_TotalLength = 1 + encoffs + enclen + (int)f.Length;

            return f;
        }

        internal static void DecodeLHPConnIds(byte[] readDgramBuf, out Memory<byte> srcId, out Memory<byte> destId)
        {
            // todo error max 20 bytes
            int destIdLen = readDgramBuf[5];
            int srcIdOffs = 5 + 1 + destIdLen;
            int srcIdLen = readDgramBuf[srcIdOffs];

            destId = new Memory<byte>(readDgramBuf, 6, destIdLen);
            srcId = new Memory<byte>(readDgramBuf, srcIdOffs, srcIdLen);
        }

        /// <summary>
        /// variable-length integer decoding
        /// </summary>
        public static ulong DecodeIntegerVLE(Span<byte> memBuffer, int offset, out int decodedBytesCount)
        {
            var buffer = memBuffer;
            ulong result = 0;
            int type = (buffer[offset] & 0xC0) >> 6;
            decodedBytesCount = (1 << type);

            switch (type)
            {
                case 0: result = buffer[offset]; break;
                case 1: result = MemMap.ToUShort2BytesBE(memBuffer, offset); break;
                case 2: result = MemMap.ToUInt4BytesBE(memBuffer, offset); break;
                case 3: result = MemMap.ToULong8BytesBE(memBuffer, offset); break;
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

        public static LongHeaderPacket DecodeLHP(byte[] buffer, int offset, bool isEncrypted, bool skipPayload = false)
        {
            LongHeaderPacket p = new LongHeaderPacket();
            LongPacketType type = LongHeaderPacket.GetLongPacketType(buffer[offset]);

            if (type == LongPacketType.Initial)
            {
                var ip = DecodeInitialPacket(buffer, offset, isEncrypted, skipPayload);

                p.FirstByte = ip.FirstByte;
                p.Version = ip.Version;
                p.DestConnIdLen = ip.DestConnIdLen;
                p.DestConId = ip.DestConId;
                p.SrcConIdLen = ip.SrcConIdLen;
                p.SrcConId = ip.SrcConId;
                p.Length = ip.Length;
                p.PacketNumber = ip.PacketNumber;
                p.Payload = ip.Payload;

                p.A_OffsetPacketNumber = ip.A_OffsetPacketNumber;
                p.A_HeaderLength = ip.A_HeaderLength;
                p.A_TotalPacketLength =ip.A_TotalPacketLength;
            }
            else if (type == LongPacketType.Handshake)
            {
                var hp = DecodeHandshakePacket(buffer, offset, isEncrypted, skipPayload);

                p.FirstByte = hp.FirstByte;
                p.Version = hp.Version;
                p.DestConnIdLen = hp.DestConnIdLen;
                p.DestConId = hp.DestConId;
                p.SrcConIdLen = hp.SrcConIdLen;
                p.SrcConId = hp.SrcConId;
                p.Length = hp.Length;
                p.PacketNumber = hp.PacketNumber;
                p.Payload = hp.Payload;

                p.A_OffsetPacketNumber = hp.A_OffsetPacketNumber;
                p.A_HeaderLength = hp.A_HeaderLength;
                p.A_TotalPacketLength = hp.A_TotalPacketLength;
            }
            else throw new NotImplementedException();

            return p;
        }

        public static HandshakePacket DecodeHandshakePacket(byte[] buffer, int offset, bool isencrypted, bool skipPayload)
        {
            var p = new HandshakePacket();

            int o = offset;

            p.FirstByte = buffer[o];
            p.Version = MemMap.ToUInt4BytesBE(buffer, offset);
            QuicModelCoding.DecodeVerDestIDSrcID(buffer, offset, out p.Version, out p.DestConId, out p.SrcConId);
            o += 1 + 4 + 1 + p.DestConId.Length + 1 + p.SrcConId.Length;

            p.Length = DecodeIntegerVLE(buffer, o, out var encLength);
            o += encLength;

            p.A_TotalPacketLength = (int)p.Length + (o - offset);
            p.A_OffsetPacketNumber = o;

            if (!isencrypted)
            {
                p.PacketNumber = Decode_LHP_RawPacketNumber(buffer, o, p.PacketNumberLength);
                o += p.PacketNumberLength + 1;

                int payloadLen = (int)((int)p.Length - p.PacketNumberLength - 1);
                
                if (!skipPayload) p.Payload = new Memory<byte>(buffer, o, payloadLen);

                p.A_HeaderLength = o - offset;
            }

            return p;
        }

        static uint Decode_LHP_RawPacketNumber(byte[] buffer, int o, int packetNumberLength)
        {
            uint r = 0;

            switch (packetNumberLength)
            {
                case 0: r = buffer[o]; break;
                case 1: r = (uint)((buffer[o] << 8) | (buffer[o + 1] << 0)); break;
                case 2: r = (uint)((buffer[o] << 16) | (buffer[o + 1] << 8) | (buffer[o + 2] << 0)); break;
                case 3: r = MemMap.ToUInt4BytesBE(buffer, o); break;
                default: QuicValidation.ThrowDecodeEx("packetNumberLength"); break;
            }

            return r;
        }

        public static InitialPacket DecodeInitialPacket(byte[] buffer, int offset, bool isEncrypted, bool skipPayload)
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
            o += lengthEncCount;

            p.A_TotalPacketLength = o - offset + (int)p.Length;
            p.A_OffsetPacketNumber = o;

            if (!isEncrypted)
            {
                p.PacketNumber = Decode_LHP_RawPacketNumber(buffer, o, p.PacketNumberLength);

                p.A_DecodedPacketNumber = 0; //todo QuicModelCoding.DecodePacketNumber(0, lhp.PacketNumber, (lhp.PacketNumberLength * 8) + 8)

                o += p.PacketNumberLength + 1;
                int payloadLen = ((int)p.Length - p.PacketNumberLength - 1);

                if (!skipPayload) p.Payload = new Memory<byte>(buffer, o, payloadLen);

                p.A_HeaderLength = o - offset;
            }

            return p;
        }

        /// <summary>
        /// encodes all fields in initial packet, payload is skipped
        /// </summary>
        /// <exception cref="NotImplementedException"></exception>
        internal static void Encode_InitialPacketSkipPayload(ByteBuffer output, InitialPacket p)
        {
            byte[] buf = output.Buffer;

            output.Append(p.FirstByte);
            int oversion = output.MallocAppend(4);
            MemMap.ToBytes1UIntBE(p.Version, output.Buffer, oversion);
            
            // dest con id len
            output.Append((byte)p.DestConnIdLen);
            output.Append(p.DestConId);

            //src con id
            output.Append((byte)p.SrcConIdLen);
            output.Append(p.SrcConId);

            // token
            Encode_IntegerVLE(output, p.TokenLen);
            output.Append(p.Token);

            // length
            Encode_IntegerVLE(output, p.Length);

            // packet number
            Encode_LHP_PacketNumber(output, p.PacketNumber, p.PacketNumberLength);
            
            // payload ignore
            // p.payload
        }

        static int Encode_LHP_PacketNumber(ByteBuffer output, uint packetNumber, int packetNumberLength)
        {
            int o = -1;
            int l = 0;

            if (packetNumberLength == 3)
            {
                o = output.MallocAppend(4);
                MemMap.ToBytes1UIntBE(packetNumber, output.Buffer, o);
                l = 4;
            }
            else if (packetNumberLength == 2)
            {
                o = output.MallocAppend(3);
                output.Buffer[o + 0] = (byte)(packetNumber >> 16);
                output.Buffer[o + 1] = (byte)(packetNumber >> 8);
                output.Buffer[o + 2] = (byte)(packetNumber >> 0);
                l = 3;
            }
            else if (packetNumberLength == 1)
            {
                o = output.MallocAppend(2);
                MemMap.ToUShort2BytesBE(output.Buffer, o);
                l = 2;
            }
            else if (packetNumberLength == 0)
            {
                output.Append((byte)packetNumber);
                l = 1;
            }
            else throw new InvalidOperationException("packetnumberlength invalid value");

            return l;
        }

        internal static ConnectionCloseFrame DecodeFrame_Close(byte[] payload, int o)
        {
            var c = new ConnectionCloseFrame();
            int initialOffset = o;

            c.Type = (FrameType)payload[o];
            o += 1;
            c.ErrorCode = DecodeIntegerVLE(payload, o, out var eclen);
            o += eclen;

            if (c.Type == FrameType.ConnectionCloseC)
            {
                c.FrameType = DecodeIntegerVLE(payload, o, out var ftlen);
                o += ftlen;
            }

            c.ReasonPhraseLength = DecodeIntegerVLE(payload, o, out var rpllen);
            o += rpllen;
            checked
            {
                c.ReasonPhrase = new Memory<byte>(payload, o, (int)c.ReasonPhraseLength);
                o += (int)c.ReasonPhraseLength;
            }

            c.A_TotalLength = o - initialOffset + 1;

            return c;
        }

        public static void EncodePacketNumber(long full_pn, long largest_acked, out uint encoded_result, out int num_bytes)
        {
            long num_unacked = 0;

            if (largest_acked < 0)
                num_unacked = full_pn + 1;
            else num_unacked = full_pn - largest_acked;

            num_unacked = num_unacked < 1 ? 1 : num_unacked;

            int min_bits = (int)Math.Log2((double)num_unacked) + 1;
            num_bytes = (int)Math.Ceiling((decimal)min_bits / 8);

            switch (num_bytes)
            {
                case 1: encoded_result = (byte)full_pn; break;
                case 2: encoded_result = (ushort)full_pn;  break;
                case 3: encoded_result = (uint)(full_pn & 0x00FFFFFF); break;
                case 4: encoded_result = (uint)full_pn; break;
                default: throw new QuicException("coding error"); break;
            }
        }

        public static long DecodePacketNumber(uint largest_pn, uint truncated_pn, int pn_nbits)
        {
            long expected_pn = largest_pn + 1;
            long pn_win = (long)1 << (int)pn_nbits;
            long pn_hwin = pn_win / 2;
            long pn_mask = pn_win - 1;

            long candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

            if (
                (candidate_pn <= expected_pn - pn_hwin) &&
                (candidate_pn < ((1 << 62) - pn_win))
                )
            {
                return candidate_pn + pn_win;
            }

            if (
                (candidate_pn > (expected_pn + pn_hwin)) &&
                candidate_pn >= pn_win
                )
            {
                return candidate_pn - pn_win;
            }

            return candidate_pn;
        }

        internal static void Encode_HandshakePacketSkipPayload(ByteBuffer output, HandshakePacket p)
        {
            byte[] buf = output.Buffer;

            output.Append(p.FirstByte);
            int oversion = output.MallocAppend(4);
            MemMap.ToBytes1UIntBE(p.Version, output.Buffer, oversion);

            // dest con id len
            output.Append((byte)p.DestConnIdLen);
            output.Append(p.DestConId);

            //src con id
            output.Append((byte)p.SrcConIdLen);
            output.Append(p.SrcConId);

            // length
            Encode_IntegerVLE(output, p.Length);

            // packet number
            Encode_LHP_PacketNumber(output, p.PacketNumber, p.PacketNumberLength);

            // payload ignore
            // p.payload
        }

        internal static object DecodeFrame_ACK(byte[] p, int i)
        {
            throw new NotImplementedException();
        }
    }
}
