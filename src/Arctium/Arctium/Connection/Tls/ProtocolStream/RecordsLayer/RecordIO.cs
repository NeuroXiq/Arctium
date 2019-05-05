using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.BinaryOps;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.IO;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    class RecordIO
    {
        BufferCache bufferCache;

        Stream innerStream;

        ///<summary>
        ///Get or set max fragment length of the read and write operation.
        ///If record length exceed this limit, <see cref="RecordIO"/> throws exception
        ///Default value is <see cref="RecordConst.MaxFragmentLength"/> (2^14 + 2048 bytes)
        ///</summary>
        public int MaxFragmentLength { get; private set; }

        ///<summary>
        ///Gets or sets read & write record header version.
        ///Default version is 0.0
        ///</summary>
        public ProtocolVersion RecordVersion { get; set; }

        ///<summary>Returns readed records count</summary>
        public ulong ReadCount { get; private set; }
        ///<summary>Returns writed records count</summary>
        public ulong WriteCount { get; private set; }


        
        ///<summary>Returns <see cref="RecordHeader"/> of the loaded record.</summary>
        ///<exception cref="InvalidOperationException">If record are not already loaded into memory.</exception>
        public RecordHeader RecordHeader { get { return GetRecordHeader(); } }

        private RecordHeader GetRecordHeader()
        {
            if (bufferCache.DataLength < RecordConst.HeaderLength)
                throw new InvalidOperationException("record are not already loaded. Load record fist to get additional data");

            return FixedRecordInfo.GetHeader(bufferCache.Buffer, 0);
        }

        public RecordIO(Stream innerStream)
        {
            this.innerStream = innerStream;
            bufferCache = new BufferCache(RecordConst.MaxTlsRecordLength);
            ReadCount = 0;
            WriteCount = 0;
            MaxFragmentLength = RecordConst.MaxFragmentLength;
            RecordVersion = new ProtocolVersion(0, 0);
        }

        ///<summary>Loads record bytes from innerStream</summary>
        ///<returns>Whole length of record</returns>
        ///<remarks>This method ensures, that at least one record with entire content is successfully readed from inner stream</remarks>
        public int LoadRecord()
        {
            LoadRecordHeader();
            int contentLength = FixedRecordInfo.FragmentLength(bufferCache.Buffer, 0);

            if (contentLength > MaxFragmentLength) throw new Exception("Record fragment length exceed 'MaxFragmentLength'");
            if (contentLength < 1) throw new Exception("readed record with empty fragment (fragment length is 0)");

            LoadRemainingFragmentBytes(contentLength);

            return contentLength + RecordConst.HeaderLength;
        }

        private void LoadRemainingFragmentBytes(int fragmentLength)
        {
            int fullLength = fragmentLength + RecordConst.HeaderLength;

            while (bufferCache.DataLength < fullLength)
            {
                int writed = bufferCache.WriteFrom(innerStream);
                if (writed < 1) throw new Exception("Cannot read from inner stream. Stream returns 0 bytes after read");
            }
        }

        private void LoadRecordHeader()
        {
            if (bufferCache.DataLength < RecordConst.LengthOffset + 2)
            {
                while (bufferCache.DataLength < RecordConst.LengthOffset + 2)
                {
                    int readed = bufferCache.WriteFrom(innerStream);
                    if (readed < 1) throw new Exception("innerStream returns 0 bytes after read");
                }
            }
        }

        public int ReadFragment(byte[] buffer, int offset)
        {
            int fragmentLength = FixedRecordInfo.FragmentLength(bufferCache.Buffer, 0);// + RecordConst.HeaderLength;
            for (int i = 0; i < fragmentLength; i++)
            {
                buffer[i] = bufferCache.Buffer[i + RecordConst.HeaderLength];
            }

            bufferCache.TrimStart(fragmentLength + RecordConst.HeaderLength);
            ReadCount++;

            return fragmentLength;
        }

        public void WriteFragment(byte[] buffer, int offset, int length, ContentType contentType)
        {
            if (length > MaxFragmentLength) throw new Exception("record fragment length exceed 'MaxFragmentLength'");

            byte[] bytes = BuildRecordBytes(buffer, offset, length, contentType);
            
            innerStream.Write(bytes, 0, bytes.Length);
            WriteCount++;
        }

        private byte[] BuildRecordBytes(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] temp = new byte[length + 2 + 1 + 2];

            temp[0] = (byte)contentType;
            temp[1] = 3;
            temp[2] = 2;
            NumberConverter.FormatUInt16((ushort)length, temp, 3);

            for (int i = 0; i < length; i++)
            {
                temp[5 + i] = buffer[i + offset];
            }

            return temp;

        }

    }
}
