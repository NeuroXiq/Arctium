using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Skein_1024 : Skein
    {
        public Skein_1024() : base(Skein.InternalStateSize.Bits_1024, 1024)
        {
        }

        protected override void HashNotLastBlockBufferCallback(byte[] buffer, long offset, long length)
        {
            SkeinAlgorithm.SimpleProcessNotLastBlock1024(context, buffer, offset, length);
        }

        protected override void HashLastBlock(byte[] buffer, long offset, long length)
        {
            SkeinAlgorithm.SimpleProcessLastBlock1024(context, buffer, offset, length);
        }
    }
}
