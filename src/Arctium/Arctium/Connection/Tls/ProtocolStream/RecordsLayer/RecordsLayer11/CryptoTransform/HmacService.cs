using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.BinaryOps;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class HmacService
    {
        public MACAlgorithm MacAlgorithm { get; private set; }
        public int HashSize { get; private set; }

        HMAC readHmac;
        HMAC writeHmac;

        public HmacService(MACAlgorithm algorithm, HMAC readHmac, HMAC writeHmac, CompressionMethod compressionMethod)
        {
            this.readHmac = readHmac;
            this.writeHmac = writeHmac;
            this.HashSize = readHmac.HashSize;

            MacAlgorithm = algorithm;
        }


        public byte[] ComputeReadHmac(byte[] buffer, int offset, int length, ulong seqNum)
        {
            if (MacAlgorithm == MACAlgorithm.NULL) return new byte[0];

            byte[] temp = new byte[length]; Array.Copy(buffer, offset, temp, 0, length);
            byte[] seqNumBytes = new byte[8];
            NumberConverter.FormatUInt64(seqNum, seqNumBytes, 0);




            //BufferTools.Join(

            return null;
        }



        public byte[] ComputeWriteHMac(byte[] buffer, int offset, int length, ulong seqNum)
        {
            if (MacAlgorithm == MACAlgorithm.NULL) return new byte[0];

            byte[] temp = new byte[length]; Array.Copy(buffer, offset, temp, 0, length);return null;
        }

    
    }
}
