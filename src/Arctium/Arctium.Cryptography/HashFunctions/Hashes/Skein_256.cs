using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Skein_256 : Skein
    {
        public Skein_256(): base(Skein.InternalStateSize.Bits_256, 256) 
        {
        }

        protected override void HashNotLastBlockBufferCallback(byte[] buffer, long offset, long length)
        {
            SkeinAlgorithm.SimpleProcessNotLastBlock256(context, buffer, offset, length);
        }

        protected override void HashLastBlock(byte[] buffer, long offset, long length)
        {
            SkeinAlgorithm.SimpleProcessLastBlock256(context, buffer, offset, length);
        }
    }
}
