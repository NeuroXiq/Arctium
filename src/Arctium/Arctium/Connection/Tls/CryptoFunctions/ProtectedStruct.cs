using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.CryptoFunctions
{
    ///<summary>
    /// Wrapper for wrapper for DPAPI.
    /// Maybe in future will be another security approach to memory security in this project. 
    /// Instead of usign hardcoded, platform-dependent 'MemoryProtection' in code this wrapper can be changed in time 
    /// to the different crypto-libs but currently it using funtions form windows crypto lib
    ///</summary>
    sealed class ProtectedStruct
    {
        private bool isNowProtected;
        private object lockObjectInstance;
        private byte[] secretBytes;

        public bool IsNowProtected
        {
            get
            {
                bool isProtected = false;
                lock (lockObjectInstance)
                {
                    isProtected =  isNowProtected;
                }

                return isProtected;
            }
        }

        private ProtectedStruct(byte[] toProtect)
        {
            isNowProtected = false;
            lockObjectInstance = new object();
            secretBytes = toProtect;
        }

        ///<summary>After creating protector ALWAYS call <see cref="ToProtected"/> method</summary>
        public static ProtectedStruct CreateProtector(byte[] source)
        {
            return new ProtectedStruct(source);
        }

        ///<summary>Decrypts stored bytes and returns reference to pain memory</summary>
        public void ToUnprotected(out byte[] decryptedReference)
        {
            bool invalidIsUnprotected = false;

            lock (lockObjectInstance)
            {
                if (isNowProtected)
                {
                    ProtectedMemory.Unprotect(secretBytes, MemoryProtectionScope.SameLogon);
                    isNowProtected = false;
                    invalidIsUnprotected = false;
                    decryptedReference = secretBytes;
                }
                else invalidIsUnprotected = true;
            }

            if (invalidIsUnprotected) throw new InvalidOperationException("Memory is already unprotected");

            decryptedReference = null;
        }

     
        ///<summary>Encrypt stored bytes</summary>
        public void ToProtected()
        {

            bool invalidIsProtected = false;
            lock (lockObjectInstance)
            {
                if (!isNowProtected)
                {
                    ProtectedMemory.Protect(secretBytes, MemoryProtectionScope.SameLogon);
                    isNowProtected = true;
                    invalidIsProtected = false;
                }
                else invalidIsProtected = true;
            }

            if (invalidIsProtected)
            {
                throw new InvalidOperationException("Cannot protect memory because is alredy encrypted");
            }

        }
    }
}
