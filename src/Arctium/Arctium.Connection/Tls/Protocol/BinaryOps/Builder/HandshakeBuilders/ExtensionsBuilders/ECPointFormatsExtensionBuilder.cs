using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class ECPointFormatsExtensionBuilder : IExtensionBuilder
    {
        public HandshakeExtension BuildExtension(ExtensionFormatData extFormatData)
        {
            //at least 1 bytes, length of the list
            if (extFormatData.Length < 1) Throw("Length of the extensions must be at least 2 bytes indicating length of EC Point format list");

            //length in bytes, 1 bytes per PointFormat
            int listLength = (int)extFormatData.Buffer[extFormatData.DataOffset];

            if (listLength + 1 != extFormatData.Length) Throw("Invalid length of the PointFormats List. list length and extension length are different");

            ECPointFormat[] pointFormats = new ECPointFormat[listLength];
            
            // 1 == first bytes indicates list length,
            int pointNumberOffset = 1 + extFormatData.DataOffset;

            for (int i = 0; i < listLength; i++)
            {
                pointFormats[i] = (ECPointFormat)extFormatData.Buffer[i + pointNumberOffset];
            }

            ECPointFormatsExtension ecPointFormats = new ECPointFormatsExtension(pointFormats);

            return ecPointFormats;

        }

        private void Throw(string v)
        {
            throw new Exception("ECPointFormatsExtensionBuilder: " + v);
        }
    }
}
