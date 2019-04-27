using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordTransform.Compression
{
    class FragmentCompressionFactory
    {
        public FragmentCompressionFactory() { }

        public FragmentCompression BuildCompression(CompressionMethod compressionMethod)
        {
            if (compressionMethod != CompressionMethod.NULL)
                throw new NotSupportedException("FragmentCompressionFactory supports only CompressionMethod.NULL");

            return new NullFragmentCompression();

        }
    }
}
