using Arctium.Protocol.Tls.Tls12.Buffers;
using Arctium.Protocol.Tls.Exceptions;
using Arctium.Protocol.Tls.Protocol;
using Arctium.Protocol.Tls.Protocol.AlertProtocol;
using Arctium.Protocol.Tls.Protocol.BinaryOps;
using Arctium.Protocol.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Protocol.Tls.Protocol.Consts;
using Arctium.Protocol.Tls.Protocol.RecordProtocol;
using System;
using System.IO;

namespace Arctium.Protocol.Tls.ProtocolStream.RecordsLayer
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

            
            if (contentLength > MaxFragmentLength) new FatalAlertException("RecordLayer12","On reading record", (int)AlertDescription.RecordOverflow, "Record fragment length exceed 'MaxFragmentLength'");
            if (contentLength < 1) throw new FatalAlertException("Record Layer 12", "On reading record", (int)AlertDescription.BadRecordMac, "Record length is 0");

            LoadRemainingFragmentBytes(contentLength);

            return contentLength + RecordConst.HeaderLength;
        }

        private void LoadRemainingFragmentBytes(int fragmentLength)
        {
            int fullLength = fragmentLength + RecordConst.HeaderLength;

            while (bufferCache.DataLength < fullLength)
            {
                int writed = bufferCache.WriteFrom(innerStream);
                if (writed < 1) throw new Exception("Cannot read from inner stream. Stream returns 0 bytes after");
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

            return fragmentLength;
        }

        public void WriteFragment(byte[] buffer, int offset, int length, ContentType contentType)
        {
            if (length > MaxFragmentLength)
            {
                string msg = string.Format("Fragment length exceed setted limit." +
                    "Current MaxFragmentLength: {0}, but tried to writes {1} bytes", MaxFragmentLength, length);

                //throw new RecordIOException(msg);
            }

            byte[] bytes = BuildRecordBytes(buffer, offset, length, contentType);
            
            innerStream.Write(bytes, 0, bytes.Length);
        }

        private byte[] BuildRecordBytes(byte[] buffer, int offset, int length, ContentType contentType)
        {
            

            byte[] temp = new byte[length + 2 + 1 + 2];

            temp[0] = (byte)contentType;
            temp[1] = RecordVersion.Major;
            temp[2] = RecordVersion.Minor;
            NumberConverter.FormatUInt16((ushort)length, temp, 3);

            for (int i = 0; i < length; i++)
            {
                temp[5 + i] = buffer[i + offset];
            }

            return temp;

        }
    }
}
