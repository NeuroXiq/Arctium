using Arctium.Connection.Tls.Crypto;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.BinaryOps;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.RecordTransform;
using Arctium.Connection.Tls.Buffers;
using System;
using System.IO;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.FormatConsts;

namespace Arctium.Connection.Tls.ProtocolStream
{
    ///<summary>Record Layer</summary>
    class RecordLayer
    {
        RecordCrypto recordCrypto;
        RecordCompression recordCompression;
        SecurityParameters currentSecParams;
        Stream innerStream;
        RecordFragmentStream fragmentsStream;
        RecordReader recordReader;

        private RecordLayer(Stream innerStream, SecurityParameters secParams)
        {
            currentSecParams = secParams;
            recordCompression = new RecordCompression(secParams.CompressionAlgorithm);

            RecordCryptoFactory recordCryptoFactory = new RecordCryptoFactory();
            recordCrypto = recordCryptoFactory.BuildRecordCrypto(secParams);

            this.innerStream = innerStream;
            fragmentsStream = new RecordFragmentStream();
            recordReader = new RecordReader(innerStream);
        }


        public static RecordLayer Initialize(Stream innerStream, ConnectionEnd connectionEnd)
        {
            SecurityParametersFactory secParamsFactory = new SecurityParametersFactory();
            SecurityParameters secParams = secParamsFactory.BuildInitialState(connectionEnd);

            return new RecordLayer(innerStream, secParams);
        }


        ///<summary>
        ///Change the current <see cref="SecurityParameters"/> state to new one. 
        ///After this operation all read and write operations will be base on this new state.
        ///</summary>
        public void ChangeCipherSpec(SecurityParameters newParameters)
        {

        }

        ///<summary>
        ///Divides, compress, encrypt and sends the higher level protocol bytes to the inner stream based on 
        ///the current <see cref="SecurityParameters"/> state.
        ///</summary>
        public void Write(byte[] buffer,int offset,int count, ContentType type)
        {
            if (count == 0) throw new Exception("invalid count param. Must be at least one byte length ");

        }

        ///<summary>Reads bytes of the higher level protocol</summary>
        public int Read(byte[] buffer, int offset, int count, out ContentType contentType)
        {
            if (!fragmentsStream.CanRead)
                LoadFragmentToFragmentsStream();

            return fragmentsStream.ReadFragment(buffer, offset, count, out contentType);
        }

        private void LoadFragmentToFragmentsStream()
        {
            int recordLength = recordReader.LoadRecord();
            byte[] tempBuf = new byte[recordLength];

            recordReader.ReadRecord(tempBuf, 0);

            // decompression
            // decrypto etc...
            //

            fragmentsStream.AppendFragment(tempBuf, 0 + RecordConst.HeaderLength, recordLength - 5, FixedRecordInfo.GetContentType(tempBuf, 0));
        }

        private TlsPlainText ReverseRecordProcessing(Record rawRecord)
        {
            Record reverseRecord = rawRecord;
            reverseRecord = DecryptRecord(reverseRecord);
            reverseRecord = DecompressRecord(reverseRecord);
            TlsPlainText plainText = BuildPlainRecord(reverseRecord);

            return plainText;
        }

        ///<summary>Determine record type based on current security params and convert to plain record</summary>
        private TlsPlainText BuildPlainRecord(Record decryptedRecord)
        {
            TlsPlainText plainRecord = new TlsPlainText();
            plainRecord.Type = decryptedRecord.Type;
            plainRecord.Version = decryptedRecord.Version;

            if (currentSecParams.BulkCipherAlgorithm == BulkCipherAlgorithm.NULL)
            {
                plainRecord.Fragment = decryptedRecord.Fragment;
                plainRecord.Length = decryptedRecord.Length;
            }
            else if (currentSecParams.CipherType == CipherType.Block)
            {
                TlsGenericBlockCipherText blockRecord = decryptedRecord as TlsGenericBlockCipherText;

                plainRecord.Fragment = blockRecord.Content;
                plainRecord.Length = (ushort)blockRecord.Content.Length;
            }
            else if (currentSecParams.CipherType == CipherType.Stream)
            {
                TlsGenericStreamCipherText streamRecord = decryptedRecord as TlsGenericStreamCipherText;

                plainRecord.Fragment = streamRecord.Content ;
                plainRecord.Length =  (ushort)streamRecord.Fragment.Length;

            }
            else throw new NotImplementedException("Not supported cipher type");

            return plainRecord;
        }

        private Record DecompressRecord(Record reverseRecord)
        {
            return recordCompression.Decompress(reverseRecord);
        }

        private Record DecryptRecord(Record reverseRecord)
        {
            return reverseRecord;
            //return recordCrypto.Decrypt(reverseRecord);
        }

        public void Write(Record record)
        {

        }





    }
}
