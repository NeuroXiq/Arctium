using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Skein_256 : Skein
    {
        public Skein_256(): base(256, 256) { }

        public override void HashBytes(byte[] buffer)
        {
            throw new NotImplementedException();
        }

        public override long HashBytes(Stream stream)
        {
            throw new NotImplementedException();
        }

        public override void HashBytes(byte[] buffer, long offset, long length)
        {
            throw new NotImplementedException();
        }

        public override byte[] HashFinal()
        {
            throw new NotImplementedException();
        }

        public override void Reset()
        {
            throw new NotImplementedException();
        }
    }
}
