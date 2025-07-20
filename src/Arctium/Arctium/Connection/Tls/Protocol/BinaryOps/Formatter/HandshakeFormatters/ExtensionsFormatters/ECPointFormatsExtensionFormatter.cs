using System;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters
{
    class ECPointFormatsExtensionFormatter : ExtensionFormatterBase
    {
        public override int GetBytes(byte[] buffer, int offset, HandshakeExtension extension)
        {
            ECPointFormatsExtension ecExtension = (ECPointFormatsExtension)extension;

            //first 1 bytes of length
            buffer[offset] = (byte)ecExtension.EcPointFormatList.Length;

            int ecPointsOffset = offset + 1;

            for (int i = 0; i < ecExtension.EcPointFormatList.Length; i++)
            {
                buffer[ecPointsOffset + i] = (byte)ecExtension.EcPointFormatList[i];
            }

            return 1 + ecExtension.EcPointFormatList.Length;
        }

        public override int GetLength(HandshakeExtension extension)
        {
            ECPointFormatsExtension ecExtension = (ECPointFormatsExtension)extension;

            return 1 + ecExtension.EcPointFormatList.Length;
        }
    }
}
