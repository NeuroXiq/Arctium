using Arctium.Cryptography.HashFunctions.Hashes;
using System;

namespace Arctium.Cryptography.Utils
{
    /// <summary>
    /// Helper class to create cryptographic algorithms
    /// </summary>
    public class CryptoAlgoFactory
    {
        /// <summary>
        /// Creates hash function from HashFunctionType enum
        /// </summary>
        /// <param name="hashFuncType">Function to create</param>
        /// <returns>Created hash function from specified type</returns>
        /// <exception cref="ArgumentException">Throws if cannot create hash function for some reasone (example: Skein_VAR needs parameters) 
        /// or if invalid enum value</exception>
        public static HashFunction CreateHashFunction(HashFunctionId hashFuncType)
        {
            HashFunction result = null;

            switch (hashFuncType)
            {
                case HashFunctionId.BLAKE2b_512: result = new BLAKE2b_512(); break;
                case HashFunctionId.BLAKE3: result = new BLAKE3(); break;
                case HashFunctionId.JH_224: result = new JH_224(); break;
                case HashFunctionId.JH_256: result = new JH_256(); break;
                case HashFunctionId.JH_384: result = new JH_384(); break;
                case HashFunctionId.JH_512: result = new JH_512(); break;
                case HashFunctionId.RadioGatun32: result = new RadioGatun32(); break;
                case HashFunctionId.RadioGatun64: result = new RadioGatun64(); break;
                case HashFunctionId.RIPEMD_160: result = new RIPEMD_160(); break;
                case HashFunctionId.SHA1: result = new SHA1(); break;
                case HashFunctionId.SHA2_224: result = new SHA2_224(); break;
                case HashFunctionId.SHA2_256: result = new SHA2_256(); break;
                case HashFunctionId.SHA2_384: result = new SHA2_384(); break;
                case HashFunctionId.SHA2_512: result = new SHA2_512(); break;
                case HashFunctionId.Skein_256: result = new Skein_256(); break;
                case HashFunctionId.Skein_512: result = new Skein_512(); break;
                case HashFunctionId.Skein_1024: result = new Skein_1024(); break;
                case HashFunctionId.Whirlpool: result = new Whirlpool(); break;
                case HashFunctionId.SHA3_224: result = new SHA3_224(); break;
                case HashFunctionId.SHA3_256: result = new SHA3_256(); break;
                case HashFunctionId.SHA3_384: result = new SHA3_384(); break;
                case HashFunctionId.SHA3_512: result = new SHA3_512(); break;
                case HashFunctionId.Streebog_256: result = new Streebog_256(); break;
                case HashFunctionId.Streebog_512: result = new Streebog_512(); break;

                case HashFunctionId.Skein_VAR: throw new InvalidOperationException("Skein_VAR requires additional parameters, cannot create"); break;
                default: throw new ArgumentException("unknow value of hashfunctiontype");
            }

            return result;
        }
    }
}
