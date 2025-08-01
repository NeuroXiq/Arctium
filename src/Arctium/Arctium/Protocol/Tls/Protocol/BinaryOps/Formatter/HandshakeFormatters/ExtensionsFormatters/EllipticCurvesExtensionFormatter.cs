using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters
{
    class EllipticCurvesExtensionFormatter : ExtensionFormatterBase
    {
        public override int GetBytes(byte[] buffer, int offset, HandshakeExtension extension)
        {

            EllipticCurvesExtension ecExt = (EllipticCurvesExtension)extension;

            //list length (2 bytes)
            // every ec has 2 bytes length
            int listLengthInBytes = ecExt.EllipticCurveList.Length * 2;

            NumberConverter.FormatUInt16((ushort)listLengthInBytes, buffer, offset);

            //now list elements
            // + 2 == above formatter listLength which preceed this values
            int nextOffset = 2 + offset;
            for (int i = 0; i < ecExt.EllipticCurveList.Length; i++)
            {
                NumberConverter.FormatUInt16((ushort)ecExt.EllipticCurveList[i], buffer, nextOffset);
                nextOffset += 2;
            }

            return nextOffset - offset;
        }

        public override int GetLength(HandshakeExtension extension)
        {
            EllipticCurvesExtension ecExtension = (EllipticCurvesExtension)extension;

            int listLength = ecExtension.EllipticCurveList.Length * 2;

            //2 == list length 2 bytes 
            int fullLength = listLength + 2;


            return fullLength;
        }
    }
}
