using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Skein_512 : Skein
    {
        public Skein_512() : base(512, 512) { }

        protected override void HashNotLastBlockBufferCallback(byte[] buffer, long offset, long length)
        {
            SkeinAlgorithm.SimpleProcessNotLastBlock512(context, buffer, offset, length);
        }

        protected override void HashLastBlock(byte[] buffer, long offset, long length)
        {
            SkeinAlgorithm.SimpleProcessLastBlock512(context, buffer, offset, length);
        }
    }
}
