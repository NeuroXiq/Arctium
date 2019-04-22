using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.RecordTransform
{
    class RecordCompression
    {
        CompressionMethod compressionMethod;

        public RecordCompression(CompressionMethod compressionMethod)
        {
            this.compressionMethod = compressionMethod;
        }


        public Record Decompress(Record record)
        {
            if (compressionMethod == CompressionMethod.NULL)
            {
                return record;
            }
            else throw new NotSupportedException();
        }
    }
}
