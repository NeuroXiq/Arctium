using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class EllipticCurvesExtensionBuilder : IExtensionBuilder
    {
        public HandshakeExtension BuildExtension(ExtensionFormatData extFormatData)
        {
            if (extFormatData.Length < 2) throw new Exception("Invalid length of the EllipticCurveExtension binary format. ECExtesions must contains at least 2 bytes indicating length of the list");

            int listLength = NumberConverter.ToUInt16(extFormatData.Buffer, extFormatData.DataOffset);

            if (listLength + 2 != extFormatData.Length) throw new Exception("Invalid length of EllopctiCuversExtension. Length do not match expected length of the extension ");

            if (listLength % 2 != 0) throw new Exception("Invalid length of the ellipticcurveextension. Length in bytes must be multiple of 2");

            //one curve is represented as  2 bytes 
            NamedCurve[] curves = new NamedCurve[listLength / 2];

            // + 2 == because first 2 bytes indicates length of the list
            int curvesOffset = extFormatData.DataOffset + 2;

            for (int i = 0; i < listLength; i += 2)
            {
                ushort curveNumber = NumberConverter.ToUInt16(extFormatData.Buffer, curvesOffset + i);
                curves[i / 2] = (NamedCurve)curveNumber;
            }

            EllipticCurvesExtension curvesExtension = new EllipticCurvesExtension();
            curvesExtension.EllipticCurveList = curves;

            return curvesExtension;
        }
    }
}
