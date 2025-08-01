using Arctium.Protocol.Tls.Protocol.RecordProtocol.Enum;
using System.IO;

namespace Arctium.Protocol.Tls.Tls12.ProtocolStream.RecordsLayer.RecordsLayer12
{
    interface IRecordCryptoFilter
    {
        ///<summary>Sets the record reader from which records will be readed</summary>
        void SetRecordReader(RecordReader recordReader);
        ///<summary>Sets write stream to write formatted records</summary>
        void SetWriteStream(Stream writeStream);
        ///<summary>Change sequence number. Initial state of the sequence number is always 0 and is incremented after each <see cref="ReadFragment(byte[], int, out ContentType)"/> call</summary>
        void SetReadSequenceNumber(ulong seqNum);

        void SetWriteSequenceNumber(ulong seqNum);

        ///<summary>Reads one record from record reader and write decrypted content to the <paramref name="buffer"/> at <paramref name="offset"/></summary>
        ///<param name="buffer">Buffer to write fragment data. Ensure that buffer length is at least minimum fragment length (2^14)</param>
        int ReadFragment(byte[] buffer, int offset, out ContentType contentType);

        ///<summary>Encrypts fragment bytes and write encrypted record to the specified inner stream setted by <see cref="SetWriteStream(Stream)"/></summary>
        ///<param name="buffer">Buffer which contains fragment data to encrypt</param>
        ///<param name="offset">Offset of the fragment data</param>
        ///<param name="length">Length of the fragment data. Length must not exceed maximum fragment length (2^14)</param>
        ///<param name="contentType">Type of the higher level protocol</param>
        void WriteFragment(byte[] buffer, int offset, int length, ContentType contentType);
    }
}