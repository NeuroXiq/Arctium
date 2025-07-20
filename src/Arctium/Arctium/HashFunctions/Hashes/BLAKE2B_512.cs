using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class BLAKE2b_512 : BLAKE2b
    {
        public const int BLAKE2b_512HashSize = 512;

        public BLAKE2b_512() : base(BLAKE2b_512HashSize) { }
    }
}
