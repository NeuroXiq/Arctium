using System;
using System.Numerics;
using Arctium.Cryptography.Ciphers.EllipticCurves;
using Arctium.Cryptography.Ciphers.EllipticCurves.Algorithms;
using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Standards.EllipticCurves
{
    public class SEC1_FpEllipticCurve
    {
       

        public enum ECPointCompression
        {
            NotCompressed,
            Compressed
        }

        public static byte[] EllipticCurvePointToOctetString(ECFpDomainParameters ecparams, ECFpPoint point, ECPointCompression compressionType)
        {
            if (compressionType == ECPointCompression.Compressed) throw new NotSupportedException();
            long len = (ecparams.p.GetBitLength() + 7) / 8;

            byte[] os = new byte[1 + 2 * len];

            byte[] x = point.X.ToByteArray(true, true);
            byte[] y = point.Y.ToByteArray(true, true);

            os[0] = 0x04;
            MemCpy.Copy(x, 0, os, 1 + len - x.Length, x.Length);
            MemCpy.Copy(y, 0, os, os.Length - y.Length, y.Length);

            return os;
        }

        public static ECFpPoint OctetStringToEllipticCurvePoint(byte[] octetString, BigInteger primeP)
        {
            BigInteger q = primeP;

            if (q.IsPowerOfTwo) throw new NotSupportedException("todo implem ent");

            byte[] qBytes = q.ToByteArray(isUnsigned: true, isBigEndian: true);
            int qLenBytes = qBytes.Length;

            if (octetString[0] != 0x04) throw new NotImplementedException(); // compressed form

            if (octetString.Length != qLenBytes + 1 && octetString.Length != (2 * qLenBytes) + 1)
            {
                throw new ArgumentException("octetstring or qlen invalid (not equal octetstring.lenth + 1 or 2 * octetstring.length + 1");
            }

            if (octetString.Length == qLenBytes + 1)
            {
                throw new NotSupportedException();
            }
            else
            {
                if ((octetString.Length - 1) % 2 != 0) throw new ArgumentException("octetstrin.Length");
                int len = (octetString.Length - 1) / 2;

                if(octetString[0] != 0x04) throw new ArgumentException("octent string not starts with 0x04");
                byte[] xBytes = new byte[len];
                byte[] yBytes = new byte[len];

                Array.Copy(octetString, 1, xBytes, 0, len);
                Array.Copy(octetString, len + 1, yBytes, 0, len);

                BigInteger x = Fp_OctetStringToFieldElement(xBytes);
                BigInteger y = Fp_OctetStringToFieldElement(yBytes);

                return new ECFpPoint(x, y);
            }

            return null;
        }

        public static BigInteger Fp_OctetStringToFieldElement(byte[] octetString)
        {
            return OctetStringToInteger(octetString);
        }

        public static byte[] IntegerToOctetString(BigInteger integer, int mLenInBytes)
        {
            if (integer >= (new BigInteger(1) << (8 * mLenInBytes))) throw new ArgumentException(nameof(mLenInBytes) + " less than integer");

            byte[] result = new byte[mLenInBytes];

            byte[] integerAsBytes = integer.ToByteArray(isUnsigned: true, isBigEndian: true);

            Array.Copy(integerAsBytes, 0, result, mLenInBytes - integerAsBytes.Length, integerAsBytes.Length);

            return result;
        }

        public static BigInteger OctetStringToInteger(byte[] octetString)
        {
            return new BigInteger(new Span<byte>(octetString), isUnsigned: true, isBigEndian: true);
        }

        public static void EllipticCurveKeyPairGenerationPrimitive()
        {

        }

        #region Signatures


       

        #endregion
    }
}
