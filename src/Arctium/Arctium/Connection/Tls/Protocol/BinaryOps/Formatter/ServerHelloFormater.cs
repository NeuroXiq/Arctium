using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter
{
    class ServerHelloFormater
    {
        public ServerHelloFormater() { }

        public int GetBytes(ServerHello serverHello, byte[] buffer, int offset)
        {
            int majVerOffset = offset;
            int minVerOffset = offset + 1;
            int randOffset = offset + 2;
            int sesIdLenOffset = offset + 34;
            int sesIdOffset = offset + 36;
            int sesIdLength = serverHello.SessionID.ID.Length;
            int cipherSuiteOffset = sesIdLenOffset + sesIdLength;
            int compressionMethodOffset = cipherSuiteOffset + 2;


            buffer[minVerOffset] = serverHello.ProtocolVersion.Major;
            buffer[majVerOffset] = serverHello.ProtocolVersion.Minor;

            FormatRandom(serverHello.Random, buffer, offset + randOffset);
            FormatSessionID(serverHello.SessionID, buffer, offset + sesIdOffset);

            NumberConverter.FormatUInt16((ushort)serverHello.CipherSuite, buffer, cipherSuiteOffset);
            buffer[compressionMethodOffset] = (byte)serverHello.CompressionMethod;

            return GetLength(serverHello);
        }

        private void FormatSessionID(SessionID sessionID, byte[] buffer, int offset)
        {
            for (int i = 0; i < sessionID.ID.Length; i++)
            {
                buffer[i + offset] = sessionID.ID[i];
            }
        }

        private void FormatRandom(HelloRandom random, byte[] buffer, int offset)
        {
            NumberConverter.FormatUInt32(random.GmtUnixTime, buffer, offset);

            for (int i = 0; i < 28; i++)
            {
                buffer[i + 4 + offset] = random.RandomBytes[i];
            }
        }

        public int GetLength(ServerHello serverHello)
        {
            int fullLength = 0;

            int versionLength = 2;
            int randomLength = 32;
            int sessionIdLength = serverHello.SessionID.ID.Length;
            int cipherSuiteLength = 2 + 2;
            int compressionMethodLength = 1 + 1;

            fullLength = versionLength +
                randomLength +
                sessionIdLength +
                cipherSuiteLength +
                compressionMethodLength;

            return fullLength;
        }
    }
}
