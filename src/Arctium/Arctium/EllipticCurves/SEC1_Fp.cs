using System;
using System.Numerics;
using Arctium.Cryptography.Ciphers.EllipticCurves;
using Arctium.Cryptography.Ciphers.EllipticCurves.Algorithms;
using Arctium.Shared;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared;

namespace Arctium.Standards.EllipticCurves
{
    public class SEC1_Fp
    {
        public enum ECPointCompression
        {
            NotCompressed,
            Compressed
        }

        public static SEC1.ECSignature ECDSA_SigningOperation(ECFpDomainParameters ecparams, HashFunctionId hashFunction, BytesRange M, byte[] dU)
        {
            var sig = SEC1_ECFpAlgorithm.ECDSA_SigningOperation(ecparams, hashFunction, M, dU);
            return new SEC1.ECSignature(sig.R, sig.S);
        }

        public static bool ECDSA_Verify(ECFpDomainParameters ecparams, HashFunctionId hashFunction, BytesRange M, ECFpPoint signingPartyPublicKey, ECSignature signature) =>
            SEC1_ECFpAlgorithm.ECDSA_Verify(ecparams, hashFunction, M, signingPartyPublicKey, signature);

        public static ECFpPoint OctetStringToEllipticCurvePoint(byte[] octetString, ECFpDomainParameters ecparams) => SEC1_ECFpAlgorithm.OctetStringToEllipticCurvePoint(octetString, ecparams);

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
