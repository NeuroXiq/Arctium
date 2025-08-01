using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;
using Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ServerHelloFormatter : HandshakeFormatterBase
    {
        struct SHOffsets
        {
            public int MinorVersion;
            public int MajorVersion;
            public int Random;
            public int SessionIdLength;
            public int SessionId;
            public int CipherSuite;
            public int CompressionMethod;
            public int ExtensionsOffset;
        }

        ExtensionsFormatter extensionsFormatter;

        public ServerHelloFormatter()
        {
            extensionsFormatter = new ExtensionsFormatter();
        }

        public override int GetBytes(byte[] buffer, int offset, Handshake handshakeMessage)
        {
            ServerHello serverHello = (ServerHello)handshakeMessage;

            SHOffsets offsets = CalculateOffsets(serverHello);

            buffer[offsets.MajorVersion + offset] = serverHello.ProtocolVersion.Major;
            buffer[offsets.MinorVersion + offset] = serverHello.ProtocolVersion.Minor;

            checked
            {
                Buffer.BlockCopy(serverHello.Random, 0, buffer, offsets.Random + offset, serverHello.Random.Length);
                buffer[offsets.SessionIdLength + offset] = (byte)serverHello.SessionID.Length;
                Buffer.BlockCopy(serverHello.SessionID, 0, buffer, offsets.SessionId + offset, serverHello.SessionID.Length);
                NumberConverter.FormatUInt16((ushort)serverHello.CipherSuite, buffer, offsets.CipherSuite + offset);
                buffer[offsets.CompressionMethod + offset] = (byte)serverHello.CompressionMethod;
            }

            int formattedExtensionsLength = extensionsFormatter.GetBytes(buffer, offsets.ExtensionsOffset + offset, serverHello.Extensions);

            return offsets.CompressionMethod + 1 + formattedExtensionsLength;
        }

        private SHOffsets CalculateOffsets(ServerHello serverHello)
        {
            SHOffsets offsets = new SHOffsets();

            offsets.MajorVersion = 0;
            offsets.MinorVersion = 1;
            offsets.Random = 2;
            offsets.SessionIdLength = 34;
            offsets.SessionId = 35;
            offsets.CipherSuite = offsets.SessionId + serverHello.SessionID.Length;
            offsets.CompressionMethod = offsets.CipherSuite + 2;
            offsets.ExtensionsOffset = offsets.CompressionMethod + 1;

            return offsets;
        }

        public override int GetLength(Handshake handshakeMsg)
        {
            ServerHello serverHello = (ServerHello)handshakeMsg;

            int fullLength = 0;

            int versionLength = 2;
            int randomLength = 32;
            int sessionIdLengthByte = 1;
            int sessionId = serverHello.SessionID.Length;
            int cipherSuite = 2;
            int compressionMethod = 1;
            int extensionsLength = extensionsFormatter.GetLength(serverHello.Extensions);

            fullLength = versionLength +
                randomLength +
                sessionIdLengthByte + 
                sessionId +
                cipherSuite +
                compressionMethod + 
                extensionsLength;

            return fullLength;
        }

        
    }
}

/*
 public byte[] GetBytes(ServerHello serverHello, byte[] buffer, int offset)
        {
            int majVerOffset = offset;
            int minVerOffset = offset + 1;
            int randOffset = offset + 2;
            int sesIdLenOffset = offset + 34;
            int sesIdOffset = offset + 36;
            int sesIdLength = serverHello.SessionID.ID.Length;
            int cipherSuiteOffset = sesIdLenOffset + sesIdLength;
            int compressionMethodOffset = cipherSuiteOffset + 2;


            buffer[majVerOffset] = serverHello.ProtocolVersion.Major;
            buffer[minVerOffset] = serverHello.ProtocolVersion.Minor;

            FormatRandom(serverHello.Random, buffer, offset + randOffset);
            buffer[sesIdLenOffset] = (byte)serverHello.SessionID.ID.Length;
            FormatSessionID(serverHello.SessionID, buffer, offset + sesIdOffset);

            NumberConverter.FormatUInt16((ushort)serverHello.CipherSuite, buffer, cipherSuiteOffset);
            buffer[compressionMethodOffset] = (byte)serverHello.CompressionMethod;

            return GetLength(serverHello);
        }

     */
