using System;

namespace Arctium.Shared.Security.SecureStorage
{
    //TODO secure sotrage
    public class SecretBytes : IDisposable
    {
        private static bool logEnabled;

        byte[] secretBytes;

        private SecretBytes(byte[] secretBytes)
        {
            this.secretBytes = secretBytes;
        }

        public static SecretBytes CreateSafeStorage(byte[] bytes) { return new SecretBytes(bytes); }
        public void GetPlainBytes(byte[] outputBuffer)
        {
            for (int i = 0; i < secretBytes.Length; i++)
            {
                outputBuffer[i] = secretBytes[i];
            }
        }

        public void Destroy() { }

        public void Dispose()
        {
            // ? ? ?
        }
    }
}
