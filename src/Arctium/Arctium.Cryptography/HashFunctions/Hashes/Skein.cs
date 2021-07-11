using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public abstract class Skein : HashFunction
    {
        protected SkeinAlgorithm.Context context;

        public Skein(int inputBlockSize, int hashSize) : base(inputBlockSize, hashSize)
        {
            context = SkeinAlgorithm.SimpleInitialise(inputBlockSize, hashSize);
        }
    }
}
