using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.FixedOps
{
    static class FixedKeyExchangeFormatter
    {
        public static byte[] FormatECDHParamsOnNamedCurve(byte[] pointX, byte[] pointY, NamedCurve curveName)
        {
            // 2 == NamedCurve 1 == Curve type ('ECCurveType' enum e.g. 'reserved'/'named'/ etc.. this method operates on 'named')
            //               == pointtype + vectorlen  
            int totalLength = 2 + pointX.Length + pointY.Length + 2 + 1;


            byte[] result = new byte[totalLength];

            result[0] = (byte)(ECCurveType.NamedCurve);
            NumberConverter.FormatUInt16((ushort)curveName, result, 1);

            result[3] = (byte)(1 + pointX.Length + pointY.Length);
            result[4] = 4;
            Buffer.BlockCopy(pointX, 0, result, 5, pointX.Length);
            Buffer.BlockCopy(pointY, 0, result, 5 + pointX.Length, pointY.Length);

            return result;
        }
    }
}

