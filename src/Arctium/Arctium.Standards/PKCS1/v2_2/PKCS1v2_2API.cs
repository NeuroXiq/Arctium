/*
 * Implementation of PKCS#1 v2.2
 * PKCS #1: RSA Cryptography Specifications Version 2.2
 * RFC 8017
 * 
 * 
 */

using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.PKCS1.v2_2.ASN1;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Arctium.Standards.PKCS1.v2_2
{
    /// <summary>
    /// Implementation of PKCS#1 v2.2
    /// PKCS #1: RSA Cryptography Specifications Version 2.2
    /// RFC 8017
    /// </summary>
    public static class PKCS1v2_2API
    {
        /// <summary>
        /// Indicates if exception (if any) should contain more detailed informations about
        /// failure. Should be false
        /// </summary>
        public static bool ShowDetailedMessageInException = false;

        /// <summary>
        /// Leading zeros are trimmed that are null are trimmed.
        /// All zero bytes from index '0' are removed until first non-zero bytes. 
        /// </summary>
        /// <param name="derEncodedBytes"></param>
        /// <returns></returns>
        public static RSAPublicKey DecodePublicKeyFromDerEncodedBytes(byte[] derEncodedBytes)
        {
            PKCS1DerDecoder derDecoder = new PKCS1DerDecoder();

            return derDecoder.DecodeRsaPublicKey(derEncodedBytes);
        }

        /// <summary>
        /// Leading zeroes are trimmed
        /// </summary>
        /// <param name="derEncodedBytes"></param>
        /// <returns></returns>
        public static RSAPrivateKey DecodePrivateKeyFromDerEncodedBytes(byte[] derEncodedBytes)
        {
            PKCS1DerDecoder derDecoder = new PKCS1DerDecoder();

            return derDecoder.DecodeRsaPrivateKey(derEncodedBytes);
        }

        /* EncryptionSchemes */

        public static byte[] RSAEP(RSAPublicKey publicKey, byte[] m)
        {
            BigInteger mAsInt = new BigInteger(new ReadOnlySpan<byte>(m), true, true);
            BigInteger nAsInt = new BigInteger(new ReadOnlySpan<byte>(publicKey.Modulus), true, true);
            BigInteger eAsInt = new BigInteger(new ReadOnlySpan<byte>(publicKey.PublicExponent), true, true);

            if (mAsInt > (nAsInt - 1))
            {
                throw new ArgumentException("message representative out of range");
            }

            BigInteger c = BigInteger.ModPow(mAsInt, eAsInt, nAsInt);

            return c.ToByteArray(true, true);
        }

        public static byte[] RSADP(PrivateKeyNDPair k, byte[] ciphertext)
        {
            BigInteger n = new BigInteger(new ReadOnlySpan<byte>(k.n), true, true);
            BigInteger d = new BigInteger(new ReadOnlySpan<byte>(k.d), true, true);
            BigInteger m = new BigInteger(new ReadOnlySpan<byte>(ciphertext), true, true);

            if (m > n - 1) throw new ArgumentException("ciphertext representative out of range");

            BigInteger plaintext = BigInteger.ModPow(m, d, n);

            return plaintext.ToByteArray();
        }

        public static byte[] RSADP(RSAPrivateKey k, byte[] ciphertext)
        {
            BigInteger p = new BigInteger(new ReadOnlySpan<byte>(k.Prime1), true, true);
            BigInteger q = new BigInteger(new ReadOnlySpan<byte>(k.Prime2), true, true);
            BigInteger dP = new BigInteger(new ReadOnlySpan<byte>(k.Exponent1), true, true);
            BigInteger dQ = new BigInteger(new ReadOnlySpan<byte>(k.Exponent2), true, true);
            BigInteger qInv = new BigInteger(new ReadOnlySpan<byte>(k.Coefficient), true, true);
            BigInteger c = new BigInteger(new ReadOnlySpan<byte>(ciphertext), true, true);

            BigInteger m1 = BigInteger.ModPow(c, dP, p);
            BigInteger m2 = BigInteger.ModPow(c, dQ, q);

            if (m1 < m2) m1 = m1 + p;

            BigInteger h = (qInv * (m1 - m2)) % p;
            BigInteger plaintextAsNumber = m2 + (q * h);
            byte[] plaintext = plaintextAsNumber.ToByteArray(true, true);

            if (plaintext.Length < k.Modulus.Length)
            {
                byte[] aligned = new byte[k.Modulus.Length];

                Buffer.BlockCopy(plaintext, 0, aligned, aligned.Length - plaintext.Length, plaintext.Length);

                plaintext = aligned;
            }

            return plaintext;
        }

        public static byte[] RSASP1(PrivateKeyNDPair k, byte[] m) { return RSADP(k, m); }

        public static byte[] RSASP1(RSAPrivateKey k, byte[] m) { return RSADP(k, m); }

        public static byte[] RSAVP1(RSAPublicKey publicKey, byte[] m) { return RSAEP(publicKey, m); }

        public static byte[] RSAES_OAEP_ENCRYPT(RSAPublicKey publicKey, byte[] M, byte[] L = null)
        {
            if (L == null) L = new byte[0];

            SHA1Managed sha1 = new SHA1Managed();
            int k = publicKey.Modulus.Length;
            int padLength = k - M.Length - (2*20) - 2;
            
            byte[] lhash = sha1.ComputeHash(L);
            byte[] DB = new byte[padLength + lhash.Length + 1 + M.Length];

            Array.Copy(lhash, 0, DB, 0, lhash.Length);
            DB[padLength + lhash.Length] = 0x01;
            Array.Copy(M, 0, DB, DB.Length - M.Length, M.Length);
            byte[] seed = RandomGenerator.GenerateNewByteArray(lhash.Length);
            byte[] dbMask = MGF(seed, k - lhash.Length - 1);
            byte[] maskedDB = new byte[DB.Length];
            for (int i = 0; i < maskedDB.Length; i++) maskedDB[i] = (byte)(DB[i] ^ dbMask[i]);
            byte[] seedMask = MGF(maskedDB, lhash.Length);
            byte[] maskedSeed = new byte[seed.Length];
            for (int i = 0; i < maskedSeed.Length; i++) maskedSeed[i] = (byte)(seedMask[i] ^ seed[i]);
            byte[] EB = new byte[k];

            Array.Copy(maskedSeed, 0, EB, 1, maskedSeed.Length);
            Array.Copy(maskedDB, 0, EB, 1 + maskedSeed.Length, maskedDB.Length);
            MemDump.HexDump(EB);
            byte[] c = RSAEP(publicKey, EB);


            return c;
        }

        private static byte[] MGF(byte[] mgfSeed, int maskLen) { return MGF1(mgfSeed, maskLen); }

        /// <summary>
        /// Mask Generation Function 1 defined in PKCS1 v2.2 (Hash algorithm: SHA1)
        /// Used as default mask generation function in this API
        /// </summary>
        /// <param name="mgfSeed"></param>
        /// <param name="maskLen"></param>
        /// <returns></returns>
        public static byte[] MGF1(byte[] mgfSeed, int maskLen)
        {
            SHA1Managed sha1 = new SHA1Managed();
            int counterMax = (int)((maskLen + 19) / 20);
            byte[] T = new byte[counterMax * 20];
            byte[] toHash = new byte[mgfSeed.Length + 4];
            Array.Copy(mgfSeed, 0, toHash, 0, mgfSeed.Length);

            for (int i = 0; i < counterMax; i++)
            {
                MemMap.ToBytes1UIntBE((uint)i, toHash, toHash.Length - 4);
                byte[] hashed = sha1.ComputeHash(toHash);

                Array.Copy(hashed, 0, T, i * 20, hashed.Length);
            }

            byte[] result = new byte[maskLen];

            Array.Copy(T, 0, result, 0, maskLen);

            return result;
        }

        public static byte[] RSAES_OAEP_DECRYPT(RSAPrivateKey privateKey, byte[] c, byte[] L = null)
        {
            int hLen = 20;
            int k = privateKey.Modulus.Length;
            SHA1Managed sha1 = new SHA1Managed();

            if (L == null) L = new byte[0];
            if (c.Length != privateKey.Modulus.Length) Throw("DECRYPTION ERROR: C length is not equal to length of the Private Key Modulus in bytes");
            if (privateKey.Modulus.Length < 2 * hLen + 2) Throw("DECRYPTION ERROR: Modulus length < 2 * hLen + 2)");

            byte[] m = RSADP(privateKey, c);
            byte[] lHash = sha1.ComputeHash(L);
            byte Y = m[0];
            byte[] maskedSeed = new byte[hLen];
            byte[] maskedDB = new byte[k - hLen - 1];

            Buffer.BlockCopy(m, 1, maskedSeed, 0, maskedSeed.Length);
            Buffer.BlockCopy(m, 1 + maskedSeed.Length, maskedDB, 0, maskedDB.Length);

            byte[] seedMask = MGF(maskedDB, hLen);
            byte[] seed = new byte[hLen];
            for (int i = 0; i < seed.Length; i++) seed[i] = (byte)(seedMask[i] ^ maskedSeed[i]);
            byte[] dbMask = MGF(seed, k - hLen - 1);
            byte[] DB = new byte[maskedDB.Length];
            for (int i = 0; i < maskedDB.Length; i++) DB[i] = (byte)(maskedDB[i] ^ dbMask[i]);

            byte[] lHash_ = new byte[hLen];

            Buffer.BlockCopy(DB, 0, lHash_, 0, 20);

            if (!MemOps.Memcmp(lHash_, lHash)) Throw("DECRYPTION ERROR: Hash of the label doesn't equal hash of the decrypted message");

            int padLen = -1;
            
            for (int i = hLen; i < DB.Length; i++)
            {
                padLen++;

                if (DB[i] == 0x01)
                {
                    break;
                }
                else if (DB[i] != 0x00) Throw("DECRYPTION ERORR: DECRYPTION ERROR: Invalid padding value in 'DB' buffer, expected '0x00' or '0x01' bytes");
            }

            int Moffset = hLen + padLen + 1;
            byte[] M = new byte[DB.Length - Moffset];

            Buffer.BlockCopy(DB, Moffset, M, 0, DB.Length - Moffset);

            return M;
        }

        public static byte[] RSAES_PKCS1_v1_5_ENCRYPT() { return null; }

        public static byte[] RSAES_PKCS1_v1_5_DECRYPT() { return null; }


        public static byte[] RSASSA_PSS_VERIFY() { return null; }


        public static byte[] RSASSA_PSS_GENERATE() { return null; }

        public static byte[] RSASSA_PKCS1_v1_5_GENERATE() { return null; }

        public static byte[] RSASSA_PKCS1_v1_5_VERIFY() { return null; }

        public static byte[] EMSA_PSS_ENCODE() { return null; }

        public static byte[] EMSA_PSS_VERIFY() { return null; }

        public static byte[] EMSA_PKCS1_v1_5() { return null; }

        private static void Throw(string msg)
        {
            if (!ShowDetailedMessageInException)
            {
                msg = "DECRYPTION ERROR";
            }

            throw new PKCS1v2_2StandardException(msg);
        }
    }
}
