using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.IO;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordTransform;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    ///<summary>Record Layer</summary>
    class RecordLayer
    {

        SecParams currentSecParams;
        RecordFragmentReader fragmentsStream;
        RecordReader recordReader;
        RecordWriter recordWriter;
        Fragmentator fragmentator;
        TlsRecordTransform tlsCiphertextTransform;

        private RecordLayer(Stream innerStream, SecParams secParams)
        {
            currentSecParams = secParams;
            fragmentator = new Fragmentator();
            fragmentsStream = new RecordFragmentReader();
            recordReader = new RecordReader(innerStream);
            recordWriter = new RecordWriter(innerStream);
            
        }

        public static RecordLayer Initialize(Stream innerStream)
        {
            SecParams initSecParams = InitSecParams();
            RecordLayer recordLayer = new  RecordLayer(innerStream, initSecParams);
            recordLayer.ChangeCipherSpec(initSecParams);

            return recordLayer;
        }

        private static SecParams InitSecParams()
        {
            SecParams initParams = new SecParams();
            initParams.KeyReadSecret = new byte[0];
            initParams.KeyWriteSecret = new byte[0];
            initParams.MacReadSecret = new byte[0];
            initParams.MacWriteSecret = new byte[0];
            initParams.RecordCryptoType = new RecordCryptoType(CipherType.Stream, BlockCipherMode.CBC, BulkCipherAlgorithm.NULL, 0, MACAlgorithm.NULL);

            return initParams;
        }
        
        ///<summary>
        ///Change the current <see cref="SecurityParameters"/> state to new one. 
        ///After this operation all read and write operations will be base on new state.
        ///</summary>
        public void ChangeCipherSpec(SecParams newParameters)
        {
            currentSecParams = newParameters;

            TlsRecordTransformFactory tctFactory = new TlsRecordTransformFactory();
            TlsRecordTransform newTransform = tctFactory.BuildTlsRecordTransform(newParameters);

            this.tlsCiphertextTransform = newTransform;
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

            
            byte[][] buffers = fragmentator.SplitToFragments(buffer, offset, count);

            for (int i = 0; i < buffers.Length; i++)
            {
                byte[] transformedFragment = 
                    tlsCiphertextTransform.ForwardTransform(buffers[i], 0, buffers[i].Length, recordReader.SequenceNumber);
                recordWriter.WriteRecord(transformedFragment, 0, transformedFragment.Length, type);
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
            tlsCiphertextTransform.ReverseTransform(tempBuf, 5, recordLength - 5, recordReader.SequenceNumber);

            fragmentsStream.AppendFragment(tempBuf, 0 + RecordConst.HeaderLength, recordLength - 5, FixedRecordInfo.GetContentType(tempBuf, 0));
        }
    }
}
