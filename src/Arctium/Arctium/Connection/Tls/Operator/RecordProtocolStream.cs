using Arctium.Connection.Tls.BinaryOps.Builder;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.RecordProtocol;
using Arctium.Connection.Tls.RecordTransform;
using Arctium.Connection.Tls.Transfer;
using System;
using System.IO;

namespace Arctium.Connection.Tls.Operator
{
    ///<summary>Record Layer</summary>
    class RecordProtocolStream
    {
        RecordTransfer recordTransfer;
        RecordCrypto recordCrypto;
        RecordCompression recordCompression;
        SecurityParameters currentSecParams;
        PlainTextRecordConverter plainTextRecordConverter;

        public RecordProtocolStream(Stream innerStream, SecurityParameters secParams)
        {
            recordTransfer = new RecordTransfer(innerStream);
            this.currentSecParams = secParams;
            plainTextRecordConverter = new PlainTextRecordConverter();
            recordCompression = new RecordCompression(secParams.CompressionAlgorithm);

            RecordCryptoFactory recordCryptoFactory = new RecordCryptoFactory();
            recordCrypto = recordCryptoFactory.BuildRecordCrypto(secParams);
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
        public void Write(byte[] data, ContentType type)
        {

        }

        ///<summary>
        ///Reads next record from the stream and performs all necessary steps to get plaintext data 
        ///based on the current <see cref="SecurityParameters"/> state.
        ///</summary>
        ///<returns>Decompressed and decrypted <see cref="TlsPlainText"/> record with bytes of the higher level protocol</returns>
        public TlsPlainText Read()
        {
            Record rawRecord = recordTransfer.Read();

            TlsPlainText plainRecord = ReverseRecordProcessing(rawRecord);

            return plainRecord;
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
            if (currentSecParams.BulkCipherAlgorithm == BulkCipherAlgorithm.NULL)
            {
                return plainTextRecordConverter.ConvertAsPlainText(decryptedRecord);
            }

            if (currentSecParams.CipherType == CipherType.Block)
            {
                TlsGenericBlockCipherText blockRecord = decryptedRecord as TlsGenericBlockCipherText;
                return plainTextRecordConverter.ConvertToPlainText(blockRecord);
            }
            else if (currentSecParams.CipherType == CipherType.Stream)
            {
                TlsGenericStreamCipherText streamRecord = decryptedRecord as TlsGenericStreamCipherText;
                return plainTextRecordConverter.ConvertToPlainText(streamRecord);
            }
            else throw new NotImplementedException("Not supported cipher type");
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
    }
}
