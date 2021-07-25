using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using System;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Skein_VAR : Skein
    {
        public Skein_VAR(InternalStateSize stateSize, int outputHashLengthInBits) : base(stateSize, outputHashLengthInBits)
        {
            if (outputHashLengthInBits < 1 ||
                outputHashLengthInBits % 8 != 0)
                throw new ArgumentException($"{outputHashLengthInBits} is not multiple of 8 ");
        }

        protected override void HashLastBlock(byte[] buffer, long offset, long length)
        {
            switch (StateSize)
            {
                case InternalStateSize.Bits_256:
                    SkeinAlgorithm.SimpleProcessLastBlock256(context, buffer, offset, length);
                    break;
                case InternalStateSize.Bits_512:
                    SkeinAlgorithm.SimpleProcessLastBlock512(context, buffer, offset, length);
                    break;
                case InternalStateSize.Bits_1024:
                    SkeinAlgorithm.SimpleProcessLastBlock1024(context, buffer, offset, length);
                    break;
                default:
                    break;
            }
        }

        protected override void HashNotLastBlockBufferCallback(byte[] buffer, long offset, long length)
        {
            switch (StateSize)
            {
                case InternalStateSize.Bits_256:
                    SkeinAlgorithm.SimpleProcessNotLastBlock256(context, buffer, offset, length);
                    break;
                case InternalStateSize.Bits_512:
                    SkeinAlgorithm.SimpleProcessNotLastBlock512(context, buffer, offset, length);
                    break;
                case InternalStateSize.Bits_1024:
                    SkeinAlgorithm.SimpleProcessNotLastBlock1024(context, buffer, offset, length);
                    break;
                default:
                    break;
            }
        }
    }
}
