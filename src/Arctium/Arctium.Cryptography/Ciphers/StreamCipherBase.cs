
using Arctium.DllGlobalShared.Security.SecureStorage;
using System.IO;

namespace Arctium.Cryptography.Ciphers
{
    public abstract class StreamCipherBase
    {
        const int KBit = 1024;
        public SecretBytes Key { get; private set; }

        public StreamCipherBase(byte[] key)
        {
            Key = SecretBytes.CreateSafeStorage(key);
        }

        public abstract int Encrypt(byte[] inputBuffer, int inputOffset, int length, byte[] outputBuffer, int outputOffset);

        public abstract int Decrypt(byte[] inputBuffer, int inputOffset, int length, byte[] outputBuffer, int outputOffset);

        public abstract int Encrypt(Stream inputStream, Stream outputStream);

        public abstract int Decrypt(Stream inputStream, Stream outputStream);

    }
}
