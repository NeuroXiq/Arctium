﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl.Model
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

        public int A_TotalPacketLength { get; internal set; }
        public int A_OffsetPacketNumber { get; internal set; }
        public int A_DecodedPacketNumber { get; internal set; }
        public int A_HeaderLength { get; internal set; }

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

        /// <summary>
        /// Create correct initial packet include valid coding for packet number (that depends on largest_ack)
        /// </summary>
        public static InitialPacket Create
            (Memory<byte> destConnId,
            Memory<byte> srcConnId,
            Memory<byte> token,
            long full_pn,
            long largest_ack,
            ulong payloadLength)
        {
            if (destConnId.Length > 255) throw new QuicInternalException("destConnId len");
            if (srcConnId.Length > 255) throw new QuicInternalException("srcConnId len");

            var p = new InitialPacket();

            QuicModelCoding.EncodePacketNumber(full_pn, largest_ack, out var encodedPacketNumber, out var encodedPkgNumBytes);

            // length: packet number encoding len + payload len
            ulong length = (ulong)encodedPkgNumBytes + (ulong)payloadLength;

            p.FirstByte = (byte)(
                (1 << 7) | // header form
                (1 << 6) | //fixed bit
                (0 << 5) | (0 << 4) | // type
                (0 << 3) | (0 << 2) | // reserved
                (byte)(encodedPkgNumBytes - 1) // packet number length
                );

            p.Version = 1;
            p.DestConnIdLen = (byte)destConnId.Length;
            p.DestConId = destConnId;
            p.SrcConIdLen = (byte)srcConnId.Length;
            p.SrcConId = srcConnId;
            p.TokenLen = (ulong)token.Length;
            p.Token = token;
            p.Length = length;
            p.PacketNumber = encodedPacketNumber;

            return p;
        }
    }
}
