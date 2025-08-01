/*
 * Algoritms for EC cryptography used in arctium project as standard algorithms.
 * Algorithms prefixed with SEC1_[...] are compilant with SEC1 standard
 * For all SEC1 algorithms see Arctium.Stardards project (SEC1)
 * 
 * Implemented by NeuroXiq 2022
 * 
 */

using Arctium.Cryptography.Utils;
using Arctium.Shared;
using Arctium.Shared.Exceptions;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using System;
using System.Numerics;

namespace Arctium.Cryptography.Ciphers.EllipticCurves.Algorithms
{
    /// <summary>
    /// Algorithms for elliptic curves used in Arctium project.
    /// Algorithms based on SEC1 Standard.
    /// </summary>
    public class SEC1_ECFpAlgorithm
    {

        public enum ECPointCompression
        {
            NotCompressed,
            Compressed
        }

        /// <summary>
        /// 4.1.3 Signing Operation
        /// </summary>
        /// <param name="M">Message to be signed</param>
        /// <param name="dU">Private key</param>
        public static ECSignature ECDSA_SigningOperation(ECFpDomainParameters ecparams, HashFunctionId hashFunction, BytesRange M, byte[] dU)
        {
            int againCount = 0;
            BigInteger s = 0, r = 0;

            do
            {
                Validation.ThrowInternal(againCount++ > 15, "this should not happen. Tried 15 times to generate signature and always fail (always zero). Aborting (all params ok?)");

                ECFpPoint R;
                byte[] kBytes = SEC1_ECFpAlgorithm.EllipticCurveKeyPairGenerationPrimitive(ecparams, out R);
                BigInteger k = new BigInteger(kBytes, true, true);
                BigInteger dUInt = new BigInteger(dU, true, true);
                BigInteger n = ecparams.n;

                r = R.X % ecparams.n;
                // byte[] hash = 
                var hashFunc = CryptoAlgoFactory.CreateHashFunction(hashFunction);
                hashFunc.HashBytes(M.Buffer, M.Offset, M.Length);
                byte[] H = hashFunc.HashFinal();
                BigInteger e = DeriveIntegerFromHash(ecparams.n, H);

                s = (MultiplicativeInverse(k, ecparams.n) * (e + (r * dUInt))) % n;
            }
            while (s.IsZero);

            return new ECSignature(r, s);
        }

        public static bool ECDSA_Verify(ECFpDomainParameters ecparams, HashFunctionId hashFunction, BytesRange M, ECFpPoint signingPartyPublicKey, ECSignature signature)
        {
            if (signature.R > ecparams.n || signature.R < 1 ||
                signature.S > ecparams.n || signature.S < 1)
                return false;

            var hashFunc = CryptoAlgoFactory.CreateHashFunction(hashFunction);
            hashFunc.HashBytes(M.Buffer, M.Offset, M.Length);
            byte[] hash = hashFunc.HashFinal();

            BigInteger e = DeriveIntegerFromHash(ecparams.n, hash);
            BigInteger u1 = (e * MultiplicativeInverse(signature.S, ecparams.n)) % ecparams.n;
            BigInteger u2 = (signature.R * MultiplicativeInverse(signature.S, ecparams.n)) % ecparams.n;

            BigInteger x1, y1, x2, y2, xr, yr;
            ScalarMultiplication(ecparams, ecparams.G, u1, out x1, out y1);
            ScalarMultiplication(ecparams, signingPartyPublicKey, u2, out x2, out y2);

            AddTwoPoints(ecparams, x1, y1, x2, y2, out xr, out yr);
            
            if (xr == 0 || yr == 0) return false;

            BigInteger v = xr % ecparams.n;
            
            bool isValid = v == signature.R;

            return isValid;
        }

        static BigInteger DeriveIntegerFromHash(BigInteger n, byte[] hash)
        {
            long bitlen = n.GetBitLength();
            long resultLength = bitlen >= 8 * hash.Length ? hash.Length : (bitlen + 7) / 8;

            BigInteger r = new BigInteger(new ReadOnlySpan<byte>(hash, 0, (int)resultLength), true, true);

            // need to shift bytes? (not exactly muyltiply of 8, so ends with zeros)
            int mod = (int)(bitlen % 8);
            if (mod != 0)
            {
                r = (r >> (8 - mod));
            }

            return r;
        }

        public static byte[] EllipticCurveKeyPairGenerationPrimitive(ECFpDomainParameters ecparams, out ECFpPoint computedPointToSendToOtherParty)
        {
            long bitslen = ecparams.n.GetBitLength();
            long bytelen = (bitslen + 7) / 8;

            byte[] rand = new byte[bytelen];
            BigInteger result = new BigInteger(rand, true, true);

            do
            {
                GlobalConfig.RandomGeneratorCryptSecure(rand, 0, (int)bytelen);
                result = new BigInteger(rand, true, true);
            } while (result >= ecparams.n);

            BigInteger rx, ry;

            ScalarMultiplication(ecparams, ecparams.G, result, out rx, out ry);

            computedPointToSendToOtherParty = new ECFpPoint(rx, ry);

            return rand;
        }

        public static ECFpPoint OctetStringToEllipticCurvePointNotCompressed(byte[] octetString, BigInteger primeP)
        {
            BigInteger q = primeP;

            if ((octetString.Length - 1) % 2 != 0) throw new ArgumentException("octetstrin.Length");
            int len = (octetString.Length - 1) / 2;

            if (octetString[0] != 0x04) throw new ArgumentException("octet string not starts with 0x04");
            byte[] xBytes = new byte[len];
            byte[] yBytes = new byte[len];

            Array.Copy(octetString, 1, xBytes, 0, len);
            Array.Copy(octetString, len + 1, yBytes, 0, len);

            BigInteger x = Fp_OctetStringToFieldElement(xBytes);
            BigInteger y = Fp_OctetStringToFieldElement(yBytes);

            return new ECFpPoint(x, y);
        }

        public static ECFpPoint OctetStringToEllipticCurvePoint(byte[] octetString, ECFpDomainParameters ecparams)
        {
            BigInteger q = ecparams.p;

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
                byte[] felementBytes = new byte[octetString.Length - 1];
                byte Y = octetString[0];
                MemCpy.Copy(octetString, 1, felementBytes, 0, felementBytes.Length);
                BigInteger xp = Fp_OctetStringToFieldElement(felementBytes);

                Validation.Argument(Y != 0x02 && Y != 0x03, nameof(octetString), "first byte should be 0x02 or 0x03");

                // BigInteger yp = Y == 0x02 ? 0 : 1;
                BigInteger yp = 0;

                BigInteger alpha = (BigInteger.ModPow(xp, 3, q) + (ecparams.a * xp) + ecparams.b) % q;

                BigInteger modType = BigInteger.ModPow(alpha, (q - 1) / 2, q) % 4;

                // modulus congruent  to 3 mod 4
                if (modType != 3) throw new NotSupportedException("modulust congruent to 3 mod 4 implemented only, other types not implemented");

                // square root of alpha in mod p (when congruent to 3 mod 4)
                BigInteger beta = BigInteger.ModPow(alpha, (q + 1) / 4, q);

                if (beta.IsEven && Y == 0) yp = beta;
                else yp = Subtract(q, q, beta);

                return new ECFpPoint(xp, yp);
            }
            else
            {
                return OctetStringToEllipticCurvePointNotCompressed(octetString, q);

                //if ((octetString.Length - 1) % 2 != 0) throw new ArgumentException("octetstrin.Length");
                //int len = (octetString.Length - 1) / 2;

                //if (octetString[0] != 0x04) throw new ArgumentException("octent string not starts with 0x04");
                //byte[] xBytes = new byte[len];
                //byte[] yBytes = new byte[len];

                //Array.Copy(octetString, 1, xBytes, 0, len);
                //Array.Copy(octetString, len + 1, yBytes, 0, len);

                //BigInteger x = Fp_OctetStringToFieldElement(xBytes);
                //BigInteger y = Fp_OctetStringToFieldElement(yBytes);

                //return new ECFpPoint(x, y);
            }

            return null;
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

        public static byte[] EllipticCurveDiffieHellmanPrimitive(ECFpDomainParameters ecparams, byte[] privKey, ECFpPoint publicKeyFromOtherParty)
        {
            BigInteger scalar = new BigInteger(privKey, true, true), outx, outy;
            ScalarMultiplication(ecparams, publicKeyFromOtherParty, scalar, out outx, out outy);

            long bytelen = (ecparams.p.GetBitLength() + 7) / 8;
            byte[] sharedSecret = new byte[bytelen];
            byte[] p = outx.ToByteArray(true, true);

            MemCpy.Copy(p, 0, sharedSecret, bytelen - p.LongLength, p.Length);

            return sharedSecret;
        }

        static void DoubleAndAddMethod(ECFpDomainParameters p, BigInteger scalar,
            ECFpPoint point,
            out BigInteger outx, out BigInteger outy)
        {
            bool isInitialized = false;
            BigInteger x = 0, y = 0;
            BigInteger tempx = point.X, tempy = point.Y;

            byte[] s = scalar.ToByteArray(isUnsigned: true, isBigEndian: false);

            for (int i = 0; i < s.Length * 8; i++)
            {
                
                bool bit = (s[i / 8] & (1 << (i % 8))) != 0;
                BigInteger rx, ry;

                if (bit)
                {
                    if (isInitialized)
                    {
                        AddTwoPoints(p, x, y, tempx, tempy, out rx, out ry);
                        x = rx;
                        y = ry;
                    }
                    else
                    {
                        isInitialized = true;
                        x = tempx;
                        y = tempy;
                    }
                }

                AddTwoPoints(p, tempx, tempy, tempx, tempy, out rx, out ry);
                tempx = rx;
                tempy = ry;
            }

            outx = x;
            outy = y;
        }

        static void AddTwoPoints(ECFpDomainParameters parms,
            BigInteger x1, BigInteger y1,
            BigInteger x2, BigInteger y2,
            out BigInteger x3, out BigInteger y3)
        {
            BigInteger p = parms.p, primeP = parms.p;

            if (x1 == 0 && y1 == 0) { x3 = x2; y3 = y2; return;}
            if (x2 == 0 && y2 == 0) { x3 = x1; y3 = y1; return; }

            if (x1 == x2)
            {
                if (x1 == 0 || y1 != y2)
                {
                    x3 = y3 = 0;
                    return;
                }
            }

            // add point to itself
            if (x1 == x2 && y1 == y2)
            {
                BigInteger lambda = FpDivision((3 * (x1 * x1) + parms.a) % p, (2 * y1) % p, p);

                x3 = Subtract(parms.p, (lambda * lambda) % p, (2 * x1) % p);
                y3 = (lambda * (Subtract(p, x1, x3))) % p;
                y3 = Subtract(p, y3, y1);
                y3 = y3 % p;
            }
            else
            {
                // add two points different x-coordinate
                BigInteger lambda = FpDivision(Subtract(primeP, y2, y1), Subtract(primeP, x2, x1), primeP);
                x3 = (lambda * lambda) % primeP ; // BigInteger.ModPow(lambda, 2, primeP);

                x3 = Subtract(primeP, x3, x1);
                x3 = Subtract(primeP, x3, x2);

                y3 = Subtract(p, x1, x3);
                y3 = Mul(p, y3, lambda);
                y3 = Subtract(p, y3, y1);
            }
        }

        static BigInteger Mul(BigInteger p, BigInteger i1, BigInteger i2)
        {
            return (i1 * i2) % p;
        }

        static void ScalarMultiplication(ECFpDomainParameters p, ECFpPoint point, BigInteger scalar, out BigInteger outx, out BigInteger outy)
        {
            DoubleAndAddMethod(p, scalar, point, out outx, out outy);
        }


        /// <summary>
        /// i1 - i2 (mod p)
        /// </summary>
        static BigInteger Subtract(BigInteger primeP, BigInteger i1, BigInteger i2)
        {
            BigInteger res = i1 - i2;

            res = res % primeP;

            if (res < 0) res += primeP;

            res %= primeP;

            if (res < 0) throw new Exception();

            return res;
        }

        /// <summary>
        /// a / b in finit field
        /// </summary>
        static BigInteger FpDivision(BigInteger a, BigInteger b, BigInteger mod)
        {
            return (a * MultiplicativeInverse(b, mod)) % mod;
        }

        public static BigInteger MultiplicativeInverse(BigInteger num, BigInteger mod)
        {
            if (num >= mod) throw new ArgumentException("num");

            BigInteger x1 = 0, y1 = 1;
            BigInteger x2 = 1, y2 = 0;
            BigInteger a = num, b = mod;
            BigInteger rem;

            BigInteger result = -1;

            while (true)
            {
                BigInteger q = BigInteger.DivRem(b, a, out rem);
                b = rem;

                x1 = x1 + (x2 * -q); y1 = y1 + (y2 * -q);

                if (rem == 0)
                {
                    if (x2 >= 0)
                    {
                        result = x2 % mod; break;
                    }
                    else
                    {
                        //BigInteger.DivRem(x2, mod, out rem);
                        result = (x2 % mod) + mod; break;
                    }
                }

                q = BigInteger.DivRem(a, b, out rem);
                a = rem;
                x2 = x2 + (x1 * -q); y1 = y2 + (y1 * -q);

                if (rem == 0)
                {
                    if (x1 >= 0)
                    {
                        result = x1 % mod;
                        break;
                    }
                    else
                    {
                        // BigInteger.DivRem(, mod, out rem);
                        result = (x1 % mod) + mod;
                        break;
                    }
                }
            }

            if ((result * num) % mod != 1)
            {
                throw new ArctiumExceptionInternal();
            }

            return result;
        }
    }
}
