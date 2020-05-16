using System;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class Blake3 : HashFunctionBase
    {
        const int InputBlockLength = 8192;

        public Blake3() : base(InputBlockLength, 12345)
        {

        }

        protected override unsafe void ExecuteHashing(byte* buffer, long length)
        {
            throw new NotImplementedException();
        }

        protected override byte[] GetCurrentHash()
        {
            throw new NotImplementedException();
        }

        protected override byte[] GetPadding()
        {
            throw new NotImplementedException();
        }

        protected override void ResetCurrentState()
        {
            throw new NotImplementedException();
        }
    }
}
