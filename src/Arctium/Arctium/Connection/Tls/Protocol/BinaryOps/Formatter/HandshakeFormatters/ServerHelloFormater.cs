﻿using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class ServerHelloFormater
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
        }

        public ServerHelloFormater() { }

        public byte[] GetBytes(ServerHello serverHello)
        {
            byte[] fBuffer = new byte[GetLength(serverHello)];

            SHOffsets offsets = CalculateOffsets(serverHello);

            fBuffer[offsets.MajorVersion] = serverHello.ProtocolVersion.Major;
            fBuffer[offsets.MinorVersion] = serverHello.ProtocolVersion.Minor;

            //FormatRandom(fBuffer, offsets.Random, serverHello.Random);
            Buffer.BlockCopy(serverHello.Random, 0, fBuffer, offsets.Random, serverHello.Random.Length);
            //FormatSessionId(fBuffer, offsets.SessionIdLength, serverHello.SessionID);
            Buffer.BlockCopy(serverHello.SessionID, 0, fBuffer, offsets.SessionId, serverHello.SessionID.Length);
            NumberConverter.FormatUInt16((ushort)serverHello.CipherSuite, fBuffer, offsets.CipherSuite);
            fBuffer[offsets.CompressionMethod] = (byte)serverHello.CompressionMethod;

            return fBuffer;
        }

        //private void FormatSessionId(byte[] fBuffer, int sesIdLengthOffset, SessionID sessionID)
        //{
        //    fBuffer[sesIdLengthOffset] = sessionID.Length;

        //    for (int i = 0; i < sessionID.Length; i++)
        //    {
        //        fBuffer[sesIdLengthOffset + 1 + i] = sessionID.ID[i];
        //    }
        //}

        //private void FormatRandom(byte[] fBuffer, int offset, HelloRandom random)
        //{
        //    NumberConverter.FormatUInt32(random.GmtUnixTime, fBuffer, offset);

        //    for (int i = 0; i < 28; i++)
        //    {
        //        fBuffer[i + offset + 4] = random.RandomBytes[i];
        //    }
        //}

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


            return offsets;
        }

        public int GetLength(ServerHello serverHello)
        {
            int fullLength = 0;

            int versionLength = 2;
            int randomLength = 32;
            int sessionIdLengthByte = 1;
            int sessionId = serverHello.SessionID.Length;
            int cipherSuite = 2;
            int compressionMethod = 1;

            fullLength = versionLength +
                randomLength +
                sessionIdLengthByte + 
                sessionId +
                cipherSuite +
                compressionMethod;

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
