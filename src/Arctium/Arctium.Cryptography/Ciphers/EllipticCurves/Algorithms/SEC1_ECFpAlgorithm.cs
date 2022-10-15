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
using Arctium.Shared.Security;
using System;
using System.Numerics;

namespace Arctium.Cryptography.Ciphers.EllipticCurves.Algorithms
{
    /// <summary>
    /// Algorithms for elliptic curves used in Arctium project.
    /// Algorithms base on SEC1 Standard.
    /// </summary>
    public class SEC1_ECFpAlgorithm
    {
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

                s = (SEC1_ECFpAlgorithm.MultiplicativeInverse(k, ecparams.n) * (e + (r * dUInt))) % n;
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
            BigInteger u1 = (e * MultiplicativeInverse(signature.S, ecparams.n));
            BigInteger u2 = (signature.R * MultiplicativeInverse(signature.S, ecparams.n));

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
            long resultLength = bitlen >= 8 * hash.Length ? (bitlen + 7) / 8 : hash.Length;

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
                GlobalConfig.RandomGeneratorCryptSecure(rand, 0, bytelen);
                result = new BigInteger(rand, true, true);
            } while (result >= ecparams.n);

            BigInteger rx, ry;

            ScalarMultiplication(ecparams, ecparams.G, result, out rx, out ry);

            computedPointToSendToOtherParty = new ECFpPoint(rx, ry);

            return rand;
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
