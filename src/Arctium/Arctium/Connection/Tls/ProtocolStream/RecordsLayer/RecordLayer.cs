using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.IO;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Crypto.ProtocolCrypto;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordTransform;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordTransform.Compression;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    ///<summary>Record Layer</summary>
    class RecordLayer
    {
        public static readonly RecordLayerTransformSuite TransformSuite = new RecordLayerTransformSuite();

        SecurityParameters currentSecParams;
        RecordFragmentReader fragmentsStream;
        RecordReader recordReader;
        RecordWriter recordWriter;
        Fragmentator fragmentator;
        FragmentCompression fragmentCompression;


        private RecordLayer(Stream innerStream, SecurityParameters secParams)
        {
            currentSecParams = secParams;
            fragmentator = new Fragmentator();
            fragmentsStream = new RecordFragmentReader();
            recordReader = new RecordReader(innerStream);
            recordWriter = new RecordWriter(innerStream);
            ChangeCipherSpec(secParams);
        }


        public static RecordLayer Initialize(Stream innerStream, ConnectionEnd connectionEnd)
        {
            SecurityParametersFactory secParamsFactory = new SecurityParametersFactory();
            SecurityParameters secParams = secParamsFactory.BuildInitialState(connectionEnd);
            RecordLayer recordLayer = new  RecordLayer(innerStream, secParams);

            return recordLayer;
        }


        ///<summary>
        ///Change the current <see cref="SecurityParameters"/> state to new one. 
        ///After this operation all read and write operations will be base on this new state.
        ///</summary>
        public void ChangeCipherSpec(SecurityParameters newParameters)
        {
            currentSecParams = newParameters;

            FragmentCompressionFactory fcf = new FragmentCompressionFactory();
            fragmentCompression = fcf.BuildCompression(newParameters.CompressionAlgorithm); 
            

        }

        ///<summary>
        ///Divides, compress, encrypt and sends the higher level protocol bytes to the inner stream based on 
        ///the current <see cref="SecurityParameters"/> state.
        ///</summary>
        public void Write(byte[] buffer, int offset, int count, ContentType type)
        {
            if (count == 0) throw new Exception("invalid count param. Must be at least one byte length ");

            // divite to 2^14 blocks
            // encrypt 
            // compress

            
            int[] buffersLengths = fragmentator.SplitToFragments(buffer, offset, count);
            int curOffset = 0;
            // encrypt
            for (int i = 0; i < buffersLengths.Length; i++)
            {
                recordWriter.WriteRecord(buffer, curOffset, buffersLengths[i], type);
                curOffset += buffersLengths[i];
            }
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

        private TlsPlaintext ReverseRecordProcessing(Record rawRecord)
        {
            Record reverseRecord = rawRecord;
            reverseRecord = DecryptRecord(reverseRecord);
            reverseRecord = DecompressRecord(reverseRecord);
            TlsPlaintext plainText = BuildPlainRecord(reverseRecord);

            return plainText;
        }

        ///<summary>Determine record type based on the current security params and convert to plain record</summary>
        private TlsPlaintext BuildPlainRecord(Record decryptedRecord)
        {
            TlsPlaintext plainRecord = new TlsPlaintext();
            plainRecord.Type = decryptedRecord.Type;
            plainRecord.Version = decryptedRecord.Version;

            if (currentSecParams.BulkCipherAlgorithm == BulkCipherAlgorithm.NULL)
            {
                plainRecord.Fragment = decryptedRecord.Fragment;
                plainRecord.Length = decryptedRecord.Length;
            }
            else if (currentSecParams.CipherType == CipherType.Block)
            {
                TlsGenericBlockCiphertext blockRecord = decryptedRecord as TlsGenericBlockCiphertext;

                plainRecord.Fragment = blockRecord.Content;
                plainRecord.Length = (ushort)blockRecord.Content.Length;
            }
            else if (currentSecParams.CipherType == CipherType.Stream)
            {
                TlsGenericStreamCiphertext streamRecord = decryptedRecord as TlsGenericStreamCiphertext;

                plainRecord.Fragment = streamRecord.Content ;
                plainRecord.Length =  (ushort)streamRecord.Fragment.Length;

            }
            else throw new NotImplementedException("Not supported cipher type");

            return plainRecord;
        }

        private Record DecompressRecord(Record reverseRecord)
        {
            return reverseRecord;
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
