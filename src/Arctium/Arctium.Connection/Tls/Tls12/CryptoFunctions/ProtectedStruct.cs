using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.Tls12.CryptoFunctions
{
    ///<summary>
    /// Wrapper for wrapper for DPAPI.
    /// Maybe in future will be another security approach to memory security in this project. 
    /// Instead of usign hardcoded, platform-dependent 'MemoryProtection' in code this wrapper can be changed in time 
    /// to the different crypto-libs but currently it using funtions form windows crypto lib
    ///</summary>
    sealed class ProtectedStruct
    {
        private readonly object lockObjectInstance;
        private byte[] secretBytes;
        private int paddingLength;
        private bool isCleared;

        private ProtectedStruct(byte[] toProtect)
        {
            lockObjectInstance = new object();
            secretBytes = toProtect;
            isCleared = false;
            CreateEncryptedBytes(toProtect);
        }

        private void CreateEncryptedBytes(byte[] toProtect)
        {
            paddingLength = 16 - (toProtect.Length % 16);
            secretBytes = new byte[toProtect.Length + paddingLength];

            for (int i = 0; i < toProtect.Length; i++)
            {
                secretBytes[i] = toProtect[i];
            }
            for (int i = 0; i < paddingLength; i++)
            {
                secretBytes[i + toProtect.Length] = (byte)paddingLength;
            }

            //ProtectedMemory.Protect(secretBytes, MemoryProtectionScope.SameLogon);
        }

        public static ProtectedStruct CreateProtector(byte[] source)
        {
            if (source == null)
                throw new ArgumentNullException("source");
            if (source.Length == 0)
                throw new ArgumentException("source buffer must contain at least one byte");


            return new ProtectedStruct(source);
        }

        ///<summary>Sets all bytes in specified buffer to 0</summary>
        public static void Clear(byte[] decryptedSecret)
        {
            for (int i = 0; i < decryptedSecret.Length; i++)
            {
                decryptedSecret[i] = 0;
            }
        }

        public byte[] GetDecrypted()
        {
            ThrowIfCleared();
            byte[] decrypted = new byte[secretBytes.Length - paddingLength];

            lock (lockObjectInstance)
            {
                //ProtectedMemory.Unprotect(secretBytes, MemoryProtectionScope.SameLogon);

                for (int i = 0; i < decrypted.Length; i++)
                    decrypted[i] = secretBytes[i];

                //ProtectedMemory.Protect(secretBytes, MemoryProtectionScope.SameLogon);
            }

            return decrypted;
        }

        private void ThrowIfCleared()
        {
            if (isCleared)
            {
                throw new InvalidOperationException("memory is cleared, object is destroyed");
            }
        }

        ///<summary>Clear stored memory. This operation cannot be undone. Object is destroyed</summary>
        public void Clear()
        {
            ThrowIfCleared();

            lock (lockObjectInstance)
            {
                for (int i = 0; i < secretBytes.Length; i++)
                {
                    secretBytes[i] = (byte)i;
                }

                secretBytes = null;
                isCleared = true;
            }
        }
    }
}
