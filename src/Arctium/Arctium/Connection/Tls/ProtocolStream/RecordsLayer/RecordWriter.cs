using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.BinaryOps;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    public class RecordWriter
    {
        Stream innerStream;

        public RecordWriter(Stream innerStream)
        {
            this.innerStream = innerStream;
        }


        public void WriteRecord(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] bytes = BuildRecordBytes(buffer, offset, length, contentType);


            //foreach (byte b in bytes)
            //{
            //    Console.Write("{0:x2} ", b);
            //}
        
            innerStream.Write(bytes, 0, bytes.Length);
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
