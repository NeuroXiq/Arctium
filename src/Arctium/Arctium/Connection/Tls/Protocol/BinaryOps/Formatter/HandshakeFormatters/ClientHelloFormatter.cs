
using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ClientHelloFormatter : HandshakeFormatterBase
    {
        struct Offsets
        {
            public int VersionOffset;
            public int RandomOffset;
            public int SessionIDLengthOffset;
            public int SessionIDOffset;
            public int CipherSuitesLengthOffset;
            public int CipherSuitesOffset;
            public int CompressionMethodsLengthOffset;
            public int CompressionMethodsOffset;
            public int ExtensionsOffset;
        }

        ExtensionsFormatter extensionsFormatter;

        public ClientHelloFormatter()
        {
            extensionsFormatter = new ExtensionsFormatter();
        }

        public override int GetBytes(byte[] buffer, int offset, Handshake handshake)
        {
            ClientHello hello = (ClientHello)handshake;

            Offsets offsets = ComputeOffsets(hello, offset);

            buffer[offsets.VersionOffset + 0] = hello.ClientVersion.Major;
            buffer[offsets.VersionOffset + 1] = hello.ClientVersion.Minor;

            Buffer.BlockCopy(hello.Random, 0, buffer, offsets.RandomOffset, hello.Random.Length);

            buffer[offsets.SessionIDLengthOffset] = (byte)hello.SessionID.Length;
            Buffer.BlockCopy(hello.SessionID, 0, buffer, offsets.SessionIDOffset, hello.SessionID.Length);

            ushort cipherSuitesLength;

            checked
            {
                cipherSuitesLength = (ushort)(2 * hello.CipherSuites.Length);
            }

            NumberConverter.FormatUInt16(cipherSuitesLength, buffer, offsets.CipherSuitesLengthOffset);
            for (int i = 0; i < hello.CipherSuites.Length; i++)
            {
                NumberConverter.FormatUInt16((ushort)hello.CipherSuites[i], buffer,
                    offsets.CipherSuitesOffset + (i * 2));
            }

            buffer[offsets.CompressionMethodsLengthOffset] = (byte)hello.CompressionMethods.Length;
            for (int i = 0; i < hello.CompressionMethods.Length; i++)
            {
                buffer[offsets.CompressionMethodsOffset + i] = (byte)hello.CompressionMethods[i];
            }

            int formattedExtenionsLength = extensionsFormatter.GetBytes(buffer, offsets.ExtensionsOffset, hello.Extensions);

            return offsets.CompressionMethodsOffset - offset + 1 + formattedExtenionsLength;
        }

        private Offsets ComputeOffsets(ClientHello hello, int shiftOffset)
        {
            Offsets offsets = new Offsets();

            offsets.VersionOffset = 0;
            offsets.RandomOffset = 2;// hello.Random.Length;
            offsets.SessionIDLengthOffset = offsets.RandomOffset + hello.Random.Length;
            offsets.SessionIDOffset = offsets.SessionIDLengthOffset + 1;
            offsets.CipherSuitesLengthOffset = offsets.SessionIDOffset + hello.SessionID.Length;
            offsets.CipherSuitesOffset = offsets.CipherSuitesLengthOffset + 2;
            offsets.CompressionMethodsLengthOffset = offsets.CipherSuitesOffset + (2 * hello.CipherSuites.Length);
            offsets.CompressionMethodsOffset = offsets.CompressionMethodsLengthOffset + 1;
            offsets.ExtensionsOffset = offsets.CompressionMethodsOffset + 1;


            offsets.VersionOffset += shiftOffset;
            offsets.RandomOffset += shiftOffset;
            offsets.SessionIDLengthOffset += shiftOffset;
            offsets.SessionIDOffset += shiftOffset;
            offsets.CipherSuitesLengthOffset += shiftOffset;
            offsets.CipherSuitesOffset += shiftOffset;
            offsets.CompressionMethodsLengthOffset += shiftOffset;
            offsets.CompressionMethodsOffset += shiftOffset;
            offsets.ExtensionsOffset += shiftOffset;


            return offsets;
        }

        public override int GetLength(Handshake handshake)
        {
            Offsets offsets = ComputeOffsets(handshake as ClientHello, 0);
            int toCompressionMethodLength = offsets.CompressionMethodsOffset + (1 * (handshake as ClientHello).CompressionMethods.Length);

            int extensionsLength = extensionsFormatter.GetLength((handshake as ClientHello).Extensions);

            return toCompressionMethodLength + extensionsLength;
        }
    }
}
