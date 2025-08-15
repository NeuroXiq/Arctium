/*
 * Implementation of PKCS#1 v2.2
 * PKCS #1: RSA Cryptography Specifications Version 2.2
 * RFC 8017
 * 
 *-----------------------------------------------------
 * Implemented by NeuroXiq 2021
 * 
 */

using Arctium.Shared;
using Arctium.Standards.PKCS1.v2_2.ASN1;
using System;
using System.Numerics;
using System.Collections.Generic;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Standards.ArctiumLibShared;

namespace Arctium.Standards.PKCS1.v2_2
{
    /// <summary>
    /// Implementation of PKCS#1 v2.2
    /// PKCS #1: RSA Cryptography Specifications Version 2.2
    /// RFC 8017
    /// <br/>
    /// All methods can throw exception, need to handle them  
    /// </summary>
    public static class PKCS1v2_2API
    {
        public class PublicKey
        {
            public int ModulusByteCount;
            public int ModulusBitsCount;

            public BigInteger Modulus;
            public BigInteger PublicExponent;

            public PublicKey(RSAPublicKey publicKey) : this(
                new BigInteger(new ReadOnlySpan<byte>(publicKey.Modulus), true, true),
                new BigInteger(new ReadOnlySpan<byte>(publicKey.PublicExponent), true, true))
            {
            }

            public PublicKey(byte[] n, byte[] e) : this(new BigInteger(new ReadOnlySpan<byte>(n), true, true), new BigInteger(new ReadOnlySpan<byte>(e), true, true))
            {
            }

            public PublicKey(BigInteger n, BigInteger e)
            {
                Modulus = n;
                PublicExponent = e;

                ModulusByteCount = Modulus.GetByteCount(true);
                ModulusBitsCount = BitsCountInModulus(n.ToByteArray(true, true));
            }

            public static PublicKey FromDefault(Arctium.Cryptography.Ciphers.RSA.RSAPublicKey defaultPublicKey)
            {
                return new PublicKey(defaultPublicKey.Modulus, defaultPublicKey.PublicExponent);
            }
        }

        /// <summary>
        /// Represents RSA private key in Chinese reminder theory (dP. dQ, qInv, public exponent, modulus)
        /// </summary>
        public class PrivateKeyCRT
        {
            public int ModulusByteCount;

            /// <summary>
            /// e
            /// </summary>
            public BigInteger PublicExponent;

            /// <summary>
            /// d
            /// </summary>
            public BigInteger PrivateExponent;

            /// <summary>
            /// p
            /// </summary>
            public BigInteger Prime1;

            /// <summary>
            /// q
            /// </summary>
            public BigInteger Prime2;

            /// <summary>
            /// d mod p - 1
            /// </summary>
            public BigInteger Exponent1;

            /// <summary>
            /// d mod q - 1
            /// </summary>
            public BigInteger Exponent2;

            /// <summary>
            /// (inverse of q) mod p
            /// </summary>
            public BigInteger Coefficient;

            /// <summary>
            /// (inverse of q) mod p
            /// </summary>
            public BigInteger Modulus;

            /// <summary>
            /// Modulus length in bits
            /// <summary>
            public int ModulusBitsCount;

            public OtherPrimeInfo[] OtherPrimeInfos { get { throw new NotImplementedException(); } }

            public PrivateKeyCRT(RSAPrivateKey privateKey)
            {
                PublicExponent = new BigInteger(new ReadOnlySpan<byte>(privateKey.PublicExponent), true, true);
                PrivateExponent = new BigInteger(new ReadOnlySpan<byte>(privateKey.PrivateExponent), true, true);
                Prime1 = new BigInteger(new ReadOnlySpan<byte>(privateKey.Prime1), true, true);
                Prime2 = new BigInteger(new ReadOnlySpan<byte>(privateKey.Prime2), true, true);
                Exponent1 = new BigInteger(new ReadOnlySpan<byte>(privateKey.Exponent1), true, true);
                Exponent2 = new BigInteger(new ReadOnlySpan<byte>(privateKey.Exponent2), true, true);
                Coefficient = new BigInteger(new ReadOnlySpan<byte>(privateKey.Coefficient), true, true);
                Modulus = new BigInteger(new ReadOnlySpan<byte>(privateKey.Modulus), true, true);
                ModulusByteCount = Modulus.GetByteCount(true);
                ModulusBitsCount = BitsCountInModulus(privateKey.Modulus);

                Validation.Argument(PublicExponent.IsZero, nameof(PublicExponent), "is zero");
                Validation.Argument(PrivateExponent.IsZero, nameof(PrivateExponent), "is zero");
                Validation.Argument(Prime1.IsZero, nameof(Prime1), "is zero");
                Validation.Argument(Prime2.IsZero, nameof(Prime2), "is zero");
                Validation.Argument(Exponent1.IsZero, nameof(Exponent1), "is zero");
                Validation.Argument(Exponent2.IsZero, nameof(Exponent2), "is zero");
                Validation.Argument(Modulus.IsZero, nameof(Modulus), "is zero");
                Validation.Argument(Coefficient.IsZero, nameof(Coefficient), "is zero");
            }
        }

        /// <summary>
        /// Represents RSA private key as a private exponent and modulus pair (d, n)
        /// </summary>
        public class PrivateKeyNDPair
        {
            public int ModulusByteCount;
            public int ModulusBitsCount;

            /// <summary>
            /// n
            /// </summary>
            public BigInteger Modulus;

            /// <summary>
            /// d
            /// </summary>
            public BigInteger PrivateExponent;

            public PrivateKeyNDPair(byte[] n, byte[] d)
            {
                Modulus = new BigInteger(new ReadOnlySpan<byte>(n), true, true);
                PrivateExponent = new BigInteger(new ReadOnlySpan<byte>(d), true, true);
                ModulusByteCount = Modulus.GetByteCount(true);
                ModulusBitsCount = BitsCountInModulus(n);
            }
        }

        /// <summary>
        /// Represents RSA private key. Key can be represented in two forms: CRT or ND pair. Internally algorithm just looks
        /// which is not null and use proper key
        /// </summary>
        public class PrivateKey
        {
            public PrivateKeyNDPair PrivateKeyNDPair;
            public PrivateKeyCRT PrivateKeyCRT;
            public int ModulusByteCount;
            public int ModulusBitsCount;

            public PrivateKey(PrivateKeyNDPair ndPair)
            {
                PrivateKeyNDPair = ndPair;
                ModulusByteCount = ndPair.ModulusByteCount;
                ModulusBitsCount = ndPair.ModulusBitsCount;
            }

            /// <summary>
            /// Initialize one of possible version of private key - Chinese reminder theory
            /// </summary>
            /// <param name="crt"></param>
            public PrivateKey(PrivateKeyCRT crt)
            {
                PrivateKeyCRT = crt;
                ModulusByteCount = crt.ModulusByteCount;
                ModulusBitsCount = crt.ModulusBitsCount;
            }

            public PrivateKey(IArctiumConvertable<PKCS1v2_2API.PrivateKeyCRT> converable) : this(converable.Convert()) { }
        }

        /// <summary>
        /// Represents mask generation function. This implementation supports
        /// custom mask generation function and this delegate represents function form
        /// </summary>
        public delegate byte[] MGF(HashFunction hashFunction, byte[] seed, int outputLength);

        /// <summary>
        /// Possible hash function for PKCS1 signatures. Not all are supported.
        /// <summary>
        public enum DigestInfoHashFunction
        {
            MD2,
            MD5,
            SHA1,
            SHA224,
            SHA256,
            SHA384,
            SHA512,
            SHA512_224,
            SHA512_256
        }

        static readonly Dictionary<DigestInfoHashFunction, byte[]> DigestInfoDerEncodedAlgoId = new Dictionary<DigestInfoHashFunction, byte[]>()
        {
            { DigestInfoHashFunction.MD2,        new byte[] { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10  } },
            { DigestInfoHashFunction.MD5,        new byte[] { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10  } },
            { DigestInfoHashFunction.SHA1,       new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14  } },
            { DigestInfoHashFunction.SHA224,     new byte[] { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c  } },
            { DigestInfoHashFunction.SHA256,     new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20  } },
            { DigestInfoHashFunction.SHA384,     new byte[] { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30  } },
            { DigestInfoHashFunction.SHA512,     new byte[] { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40  } },
            { DigestInfoHashFunction.SHA512_224, new byte[] { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c  } },
            { DigestInfoHashFunction.SHA512_256, new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20  } }
        };

        static int BitsCountInModulus(byte[] modulus)
        {
            int minus = 0;
            for (int i = 0; i < modulus.Length * 8; i++)
            {
                if ((modulus[i / 8] & (1 << (7 - (i % 8)))) == 0) minus++;
                else break;
            }

            return (modulus.Length * 8) - minus;
        }

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
        // public static RSAPublicKey DecodePublicKeyFromDerEncodedBytes(byte[] derEncodedBytes)
        // {
        //     PKCS1DerDecoder derDecoder = new PKCS1DerDecoder();
        // 
        //     return derDecoder.DecodeRsaPublicKey(derEncodedBytes);
        // }

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

        public static BigInteger RSAEP(PublicKey publicKey, byte[] m)
        {
            BigInteger mAsInt = new BigInteger(new ReadOnlySpan<byte>(m), true, true);
            BigInteger nAsInt = publicKey.Modulus;
            BigInteger eAsInt = publicKey.PublicExponent;

            if (mAsInt > (nAsInt - 1))
            {
                throw new ArgumentException("message representative out of range");
            }

            BigInteger c = BigInteger.ModPow(mAsInt, eAsInt, nAsInt);

            return c;
        }

        public static BigInteger RSADP(PrivateKeyNDPair k, byte[] ciphertext)
        {
            BigInteger n = k.Modulus;
            BigInteger d = k.PrivateExponent;
            BigInteger m = new BigInteger(new ReadOnlySpan<byte>(ciphertext), true, true);

            if (m > n - 1) throw new ArgumentException("ciphertext representative out of range");

            BigInteger plaintext = BigInteger.ModPow(m, d, n);

            return plaintext;
        }

        public static BigInteger RSADP(PrivateKeyCRT k, byte[] ciphertext)
        {
            BigInteger p = k.Prime1;
            BigInteger q = k.Prime2;
            BigInteger dP = k.Exponent1;
            BigInteger dQ = k.Exponent2;
            BigInteger qInv = k.Coefficient;
            BigInteger c = new BigInteger(new ReadOnlySpan<byte>(ciphertext), true, true);

            BigInteger m1 = BigInteger.ModPow(c, dP, p);
            BigInteger m2 = BigInteger.ModPow(c, dQ, q);

            if (m1 < m2) m1 = m1 + p;

            BigInteger h = (qInv * (m1 - m2)) % p;
            BigInteger plaintextAsNumber = m2 + (q * h);

            return plaintextAsNumber;
        }

        /// <summary>
        /// NOT PART OF API / public if needed to use externally
        /// <summary>
        public static BigInteger RSADP(PrivateKey privateKey, byte[] ciphertext)
        {
            if (privateKey.PrivateKeyNDPair != null) return RSADP(privateKey.PrivateKeyNDPair, ciphertext);
            
            return RSADP(privateKey.PrivateKeyCRT, ciphertext);
        }

        /// <summary>
        /// NOT PART OF API / public because maybe it will be useful
        /// <summary>
        public static BigInteger RSASP1(PrivateKey k, byte[] m) { return RSADP(k, m); }

        /// <summary>
        /// NOT PART OF API / public if needed to use externally
        /// </summary>
        public static BigInteger RSAVP1(PublicKey publicKey, byte[] m) { return RSAEP(publicKey, m); }


        /// <summary>
        /// Encryption scheme with Optimal Assymetric Encryption Padding (OAEP). 
        /// Label, hash function and MGF are optional and can be customized. If optional values are null,
        /// then default values are:L = empty label (0 bytes), hashFunction = SHA1, mgf = MGF1 (from standard)
        /// </summary>
        public static byte[] RSAES_OAEP_ENCRYPT(PublicKey publicKey, byte[] M, byte[] L = null, HashFunction hashFunction = null, MGF mgf = null)
        {
            if (L == null) L = new byte[0];
            if (hashFunction == null) hashFunction = new SHA1();
            if (mgf == null) mgf = MGF1;

            int k = publicKey.ModulusByteCount;
            int padLength = k - M.Length - (2 * hashFunction.HashSizeBytes) - 2;
            if (k - (2 * hashFunction.HashSizeBytes) - 2 < 1) Throw("invalid hash function (hash length greater that possible encryption)");
            if (M.Length > k - (2 * hashFunction.HashSizeBytes) - 2) Throw("message too long");

            byte[] lhash = ComputeHash(hashFunction, L);
            byte[] DB = new byte[padLength + lhash.Length + 1 + M.Length];

            Array.Copy(lhash, 0, DB, 0, lhash.Length);
            DB[padLength + lhash.Length] = 0x01;
            Array.Copy(M, 0, DB, DB.Length - M.Length, M.Length);
            byte[] seed = RandomGenerator.GenerateNonZeroNewByteArray(lhash.Length);
            byte[] dbMask = mgf(hashFunction, seed, k - lhash.Length - 1);
            
            byte[] maskedDB = new byte[DB.Length];
            for (int i = 0; i < maskedDB.Length; i++) maskedDB[i] = (byte)(DB[i] ^ dbMask[i]);
            byte[] seedMask = mgf(hashFunction, maskedDB, lhash.Length);
            byte[] maskedSeed = new byte[seed.Length];
            for (int i = 0; i < maskedSeed.Length; i++) maskedSeed[i] = (byte)(seedMask[i] ^ seed[i]);
            byte[] EB = new byte[k];

            Array.Copy(maskedSeed, 0, EB, 1, maskedSeed.Length);
            Array.Copy(maskedDB, 0, EB, 1 + maskedSeed.Length, maskedDB.Length);
            
            BigInteger ciphertextAsInteger = RSAEP(publicKey, EB);
            byte[] ciphertextAsBytes = I2OSP(ciphertextAsInteger, publicKey.ModulusByteCount);

            return ciphertextAsBytes;
        }

        // private static byte[] MGF(byte[] mgfSeed, int maskLen) { return MGF1(mgfSeed, maskLen); }

        /// <summary>
        /// Mask Generation Function 1 defined in PKCS1 v2.2 (Hash algorithm: SHA1)
        /// Used as default mask generation function in this API
        /// </summary>
        /// <param name="mgfSeed"></param>
        /// <param name="maskLen"></param>
        /// <returns></returns>
        public static byte[] MGF1(HashFunction hashFunction, byte[] mgfSeed, int maskLen)
        {
            int hLen = hashFunction.HashSizeBytes;
            int counterMax = (int)((maskLen + (hLen - 1)) / hLen);
            byte[] T = new byte[counterMax * hLen];
            byte[] toHash = new byte[mgfSeed.Length + 4];
            Array.Copy(mgfSeed, 0, toHash, 0, mgfSeed.Length);

            for (int i = 0; i < counterMax; i++)
            {
                MemMap.ToBytes1UIntBE((uint)i, toHash, toHash.Length - 4);
                byte[] hashed = ComputeHash(hashFunction, toHash);

                Array.Copy(hashed, 0, T, i * hLen, hashed.Length);
            }

            byte[] result = new byte[maskLen];

            Array.Copy(T, 0, result, 0, maskLen);

            return result;
        }



        /// <summary>
        /// NOT PART OF API / public if needed to use externally
        /// <summary>
        public static byte[] I2OSP(BigInteger integer, int k)
        {
            byte[] m = integer.ToByteArray(true, true);

            if (m.Length == k) return m;
            if (m.Length > k) Throw("I2OSP: INTERNAL ERROR mlen > k");

            byte[] r = new byte[k];
            Buffer.BlockCopy(m, 0, r, k - m.Length, m.Length);

            return r;
        }

        /// <summary>
        /// Decrypts RSA encoded message with Optimal Assymetric Encryption Padding (OEAP). 
        /// Label, HashFunction and MGF functions are optional and must be same for encryption and decryption.
        /// If not specified, default values: Label = null (0 bytes), hash function = SHA1, mgf = MGF1
        /// </summary>
        public static byte[] RSAES_OAEP_DECRYPT(PrivateKey privateKey, byte[] c, byte[] L = null, HashFunction hashFunction = null, MGF mgf = null)
        {
            if (hashFunction == null) hashFunction = new SHA1();
            if (mgf == null) mgf = MGF1;

            int hLen = hashFunction.HashSizeBytes;
            int k = privateKey.ModulusByteCount;

            if (L == null) L = new byte[0];
            if (c.Length != privateKey.ModulusByteCount) Throw("DECRYPTION ERROR: C length is not equal to length of the Private Key Modulus in bytes");
            if (privateKey.ModulusByteCount < 2 * hLen + 2) Throw("DECRYPTION ERROR: Modulus length < 2 * hLen + 2)");

            BigInteger mAsInteger = RSADP(privateKey, c);
            byte[] m = I2OSP(mAsInteger, privateKey.ModulusByteCount);
            
            byte[] lHash = ComputeHash(hashFunction, L);
            byte Y = m[0];
            byte[] maskedSeed = new byte[hLen];
            byte[] maskedDB = new byte[k - hLen - 1];

            Buffer.BlockCopy(m, 1, maskedSeed, 0, maskedSeed.Length);
            Buffer.BlockCopy(m, 1 + maskedSeed.Length, maskedDB, 0, maskedDB.Length);

            byte[] seedMask = mgf(hashFunction, maskedDB, hLen);
            byte[] seed = new byte[hLen];
            for (int i = 0; i < seed.Length; i++) seed[i] = (byte)(seedMask[i] ^ maskedSeed[i]);
            byte[] dbMask = mgf(hashFunction, seed, k - hLen - 1);
            
            byte[] DB = new byte[maskedDB.Length];
            for (int i = 0; i < maskedDB.Length; i++) DB[i] = (byte)(maskedDB[i] ^ dbMask[i]);

            byte[] lHash_ = new byte[hLen];

            Buffer.BlockCopy(DB, 0, lHash_, 0, hLen);

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

        /// <summary>
        /// Old Encryption scheme with PKCS 1.5 padding
        /// </summary>
        public static byte[] RSAES_PKCS1_v1_5_ENCRYPT(PublicKey publicKey, byte[] M)
        {
            int k = publicKey.ModulusByteCount, mLen = M.Length;
            byte[] EM;

            if (mLen > k - 11) Throw("Message too long");

            EM = new byte[k];

            EM[0] = 0x00;
            EM[1] = 0x02;
            EM[k - mLen - 1] = 0x00; 
            RandomGenerator.GenerateNonZero(EM, 2, k - mLen - 3);
            Buffer.BlockCopy(M, 0, EM, EM.Length - mLen, mLen);
            
            BigInteger ciphertextAsInteger = RSAEP(publicKey, EM);
            byte[] ciphertextAsBytes = I2OSP(ciphertextAsInteger, k);

            return ciphertextAsBytes;
        }

        /// <summary>
        /// Old decryption scheme with PKCS 1.5 padding
        /// </summary>
        public static byte[] RSAES_PKCS1_v1_5_DECRYPT(PrivateKey privateKey, byte[] M)
        {
            int k = privateKey.ModulusByteCount, psLength = 0;
            if (M.Length != k) Throw("decryption error");

            BigInteger mAsInteger = RSADP(privateKey, M);
            byte[] EB = I2OSP(mAsInteger, k);
            
            while (psLength + 2 < k && EB[psLength + 2] != 0) psLength++;

            if (EB[0] != 0x00 || EB[1] != 0x02 || psLength < 8 || psLength + 2 == k) Throw("Decryption Error");
            
            byte[] plaintext = new byte[k - 3 - psLength];
            Buffer.BlockCopy(EB, k - plaintext.Length, plaintext, 0, plaintext.Length);

            return plaintext;
        }


        /// <summary>
        /// Invokes <see cref="RSASSA_PSS_SIGN(PrivateKey, byte[], int, HashFunction, MGF)"/>
        /// With sLen = hashFunction.HashSizeInBytes (seed length equal to hash size in bytes),
        /// MGF = null (means default MGF from standard)
        /// </summary>
        public static byte[] RSASSA_PSS_SIGN(PrivateKey privateKey, byte[] M, HashFunctionId hashFunction)
        {
            HashFunction hashFunc = CryptoAlgoFactory.CreateHashFunction(hashFunction);

            return RSASSA_PSS_SIGN(privateKey, M, hashFunc.HashSizeBytes, hashFunc, null);
        }

        /// <summary>
        /// PSS Signature. Method generated Probabilistic Signature Scheme and returns signature as byte array.
        /// sLen (seed length), hash function and MGF are optional. 
        /// If not specified, then sLen = 0, hashFunction = SHA1 and MGF = MGF1 (from standard)
        /// </summary>
        public static byte[] RSASSA_PSS_SIGN(PrivateKey privateKey, byte[] M, int sLen = 0, HashFunction hashFunction = null, MGF mgf = null)
        {
            byte[] EM = EMSA_PSS_ENCODE(M, privateKey.ModulusBitsCount - 1, sLen, hashFunction, mgf);
            BigInteger sAsInt = RSASP1(privateKey, EM);
            byte[] sAsBytes = I2OSP(sAsInt, privateKey.ModulusByteCount);
            
            return sAsBytes;
        }

        /// <summary>
        /// Verifies PSS Signature. Method invokes <see cref="RSASSA_PSS_VERIFY(PublicKey, byte[], byte[], int, HashFunction, MGF)"/>
        /// With sLen (seedLength) equal to hash function output length,
        /// hashFunction equal to hashFunctionId in parameters, MGF equal to MGF1 (default from standard, maskgenerationfunction).
        /// This is common/popular algorithm for signature verification
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="M">Message signed with private key</param>
        /// <param name="S">Signature to be verified</param>
        /// <param name="hashFunctionId">Hash functinon used in signature generation algorithm</param>
        /// <returns></returns>
        public static bool RSASSA_PSS_VERIFY(PublicKey publicKey, byte[] M, byte[] S, HashFunctionId hashFunctionId)
        {
            var hashFunc = CryptoAlgoFactory.CreateHashFunction(hashFunctionId);

            return RSASSA_PSS_VERIFY(publicKey, M, S, hashFunc.HashSizeBytes, hashFunc, null);
        }

        /// <summary>
        /// PSS Signature verification. If signature is valid returns true otherwise false.
        /// M - Message to verify, S - Signature.
        /// sLen (seed length), hash function and MGF are optional. If not specified, then:
        /// sLen = 0 (0 bytes), hash function = SHA1, mgf = MGF1
        /// </summary>
        public static bool RSASSA_PSS_VERIFY(PublicKey publicKey, byte[] M, byte[] S, int sLen = 0, HashFunction hashFunction = null, MGF mgf = null)
        {
            int k = publicKey.ModulusByteCount, emLen = -1;
            BigInteger m;
            byte[] EM;

            emLen = publicKey.ModulusBitsCount / 8;

            if (publicKey.ModulusBitsCount % 8 != 0) emLen++;

            if (S.Length != k) Throw("Invalid Signature");
            
            m = RSAVP1(publicKey, S);
            EM = I2OSP(m, emLen);

            bool result = EMSA_PSS_VERIFY(M, EM, publicKey.ModulusBitsCount - 1, sLen, hashFunction, mgf);

            return result;
        }

        /// <summary>
        /// Old signature scheme generations PKCS 1.5 . Generates signature are returns signature as byte array.
        /// M - message to be signed
        /// </summary>
        public static byte[] RSASSA_PKCS1_v1_5_GENERATE(PrivateKey privateKey, byte[] M, DigestInfoHashFunction hashFunctionType = DigestInfoHashFunction.SHA1)
        {
            byte[] EM, sAsBytes;
            BigInteger sAsInteger;

            EM = EMSA_PKCS1_v1_5_ENCODE(M, privateKey.ModulusByteCount, hashFunctionType);
            sAsInteger = RSASP1(privateKey, EM);
            sAsBytes = I2OSP(sAsInteger, privateKey.ModulusByteCount);

            return sAsBytes;
        }

        /// <summary>
        /// Old Signature verification scheme PKCS 1.5. If signature is valid returns true otherwise false.
        /// M - message to be verified, S - signature
        /// </summary>
        public static bool RSASSA_PKCS1_v1_5_VERIFY(PublicKey publicKey, byte[] M, byte[] S, DigestInfoHashFunction hashFunctionType = DigestInfoHashFunction.SHA1)
        {
            BigInteger mAsInteger;
            byte[] EM, EM_;

            if (S.Length != publicKey.ModulusByteCount) Throw("Invalid signature");

            mAsInteger = RSAVP1(publicKey, S);
            EM = I2OSP(mAsInteger, publicKey.ModulusByteCount);
            EM_ = EMSA_PKCS1_v1_5_ENCODE(M, publicKey.ModulusByteCount, hashFunctionType);

            return MemOps.Memcmp(EM_, EM);
        }

        /// <summary>
        /// NOT PART OF API / public if needed to use externally
        /// </summary>
        public static byte[] EMSA_PSS_ENCODE(byte[] M, int emBits, int sLen = 0, HashFunction hashFunction = null, MGF mgf = null)
        {
            if (hashFunction == null) hashFunction = new SHA1();
            if (mgf == null) mgf = MGF1;

            byte[] M_, H, DB, mHash, salt, dbMask, EM;
            int hLen = hashFunction.HashSizeBytes, emLen, bitsCountToSetToZero = -1;

            emLen = emBits / 8;
            if (emBits % 8 != 0) emLen++;

            mHash = ComputeHash(hashFunction, M);
            
            if (emLen < hLen + sLen + 2) Throw("Encoding error");

            M_ = new byte[8 + hLen + sLen];
            salt = new byte[sLen];

            RandomGenerator.Generate(salt, 0, sLen);
            Buffer.BlockCopy(salt, 0, M_, M_.Length - sLen, sLen);
            Buffer.BlockCopy(mHash, 0, M_, 8, hLen);

            H = ComputeHash(hashFunction, M_);
            DB = new byte[emLen - hLen - 1];
            DB[emLen - sLen - hLen  - 2] = 0x01;
            Buffer.BlockCopy(salt, 0, DB, emLen - sLen - hLen - 1, sLen);
            dbMask = mgf(hashFunction, H, emLen - hLen - 1);
            
            for (int i = 0; i < dbMask.Length; i++) DB[i] ^= dbMask[i];

            bitsCountToSetToZero = (8 * emLen) - emBits;
            
            for (int i = 0; i < bitsCountToSetToZero; i++)
            {
                byte clearBit = (byte)(~(1 << (7 - (i % 8))));
                DB[i / 8] &= clearBit;
            }

           EM = new byte[DB.Length + hLen + 1];
           Buffer.BlockCopy(DB, 0, EM, 0, DB.Length);
           Buffer.BlockCopy(H, 0, EM, DB.Length, hLen);
           EM[EM.Length - 1] = 0xbc;

           return EM;
        }

        /// <summary>
        /// NOT PART OF API / public if needed to use externally
        /// </summary>
        public static bool EMSA_PSS_VERIFY(byte[] M, byte[] EM, int emBits, int sLen = 0, HashFunction hashFunction = null, MGF mgf = null)
        {
            if (hashFunction == null) hashFunction = new SHA1();
            if (mgf == null) mgf = MGF1;

            byte[] mHash, dbMask, maskedDB, DB, M_, H_, H;
            int emLen, hLen = hashFunction.HashSizeBytes, zeroBitsCount;

            emLen = emBits / 8;
            if (emBits % 8 != 0) emLen++;

            mHash = ComputeHash(hashFunction, M);
            if (emLen < hLen + sLen + 2) Throw("inconsistent");

            if (EM[EM.Length - 1] != 0xbc) Throw("inconsistent");

            zeroBitsCount = (8 * emLen) - emBits;
            for (int i = 0; i < zeroBitsCount; i++)
                if ((EM[i / 8] & (1 << (7 - (i % 8)))) != 0) Throw("inconsistent");

            H = new byte[hLen];
            Buffer.BlockCopy(EM, emLen - hLen - 1, H, 0, hLen);

            maskedDB = new byte[emLen - hLen - 1];
            DB = new byte[maskedDB.Length];
            Buffer.BlockCopy(EM, 0, maskedDB, 0, emLen - hLen - 1);
            dbMask = mgf(hashFunction, H, emLen - hLen);

            
            for (int i = 0; i < DB.Length; i++) DB[i] = (byte)(dbMask[i] ^ maskedDB[i]);

            for (int i = 0; i < zeroBitsCount; i++)
                DB[i / 8] &= (byte)~(1 << (7 - (i % 8)));

            M_ = new byte[8 + hLen + sLen];
            Buffer.BlockCopy(DB, DB.Length - sLen, M_, M_.Length - sLen, sLen);
            Buffer.BlockCopy(mHash, 0, M_, 8, hLen);
            H_ = ComputeHash(hashFunction, M_);

            bool consistent = MemOps.Memcmp(H_, H);

            return consistent;
        }

        /// <summary>
        /// NOT PART OF API / public if needed to use externally
        /// </summary>
        public static byte[] EMSA_PKCS1_v1_5_ENCODE(byte[] M, int emLen, DigestInfoHashFunction hashFunctionType)
        {
            HashFunction hashFunction = HashFunctionFactory(hashFunctionType);
            byte[] H, EM, derEncodedAlgo;
            int tLen;

            H = ComputeHash(hashFunction, M);
            derEncodedAlgo = DigestInfoDerEncodedAlgoId[hashFunctionType];

            tLen = H.Length + derEncodedAlgo.Length;

            if (emLen < tLen + 11) Throw("intended encoded message too short");

            EM = new byte[emLen];
            
            EM[0] = 0x00;
            EM[1] = 0x01;
            for (int i = 2; i < emLen - tLen - 1; i++) EM[i] = 0xFF;
            EM[emLen - tLen - 1] = 0x00;

            Buffer.BlockCopy(derEncodedAlgo, 0, EM, EM.Length - tLen, derEncodedAlgo.Length);
            Buffer.BlockCopy(H, 0, EM, EM.Length - tLen + derEncodedAlgo.Length, H.Length);

            return EM;
        }

        private static HashFunction HashFunctionFactory(DigestInfoHashFunction hashFunctionType)
        {
            switch (hashFunctionType)
            {
                case DigestInfoHashFunction.MD2: throw new NotSupportedException();
                case DigestInfoHashFunction.MD5:  throw new NotSupportedException();     
                case DigestInfoHashFunction.SHA1: return new SHA1();     
                case DigestInfoHashFunction.SHA224: return new SHA2_224();
                case DigestInfoHashFunction.SHA256: return new SHA2_256();
                case DigestInfoHashFunction.SHA384: return new SHA2_384();   
                case DigestInfoHashFunction.SHA512: return new SHA2_512();
                case DigestInfoHashFunction.SHA512_224: throw new NotSupportedException();
                case DigestInfoHashFunction.SHA512_256: throw new NotSupportedException();
                default: throw new ArgumentException();
            }
        }
        
        private static byte[] ComputeHash(HashFunction hash, byte[] m)
        {
            byte[] result;

            hash.HashBytes(m);
            result = hash.HashFinal();
            hash.Reset();

            return result;
        }

        private static void Throw(string msg)
        {
            if (!ShowDetailedMessageInException)
            {
                msg = "ERROR";
            }

            throw new PKCS1v2_2StandardException(msg);
        }
    }
}
