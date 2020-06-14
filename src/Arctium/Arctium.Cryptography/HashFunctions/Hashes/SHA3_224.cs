using System;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA3_224 : HashFunctionBase
    {
        const int R_SpongeParam = 1600 - 448;

        readonly SHA3_Shared sha3Shared;

        public SHA3_224() : base(R_SpongeParam, 224)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
        }

        protected override void ExecuteHashing(byte* buffer, long length)
        {
            sha3Shared.MainHashComputation(buffer, length);
        }

        protected override byte[] GetCurrentHash()
        {
            byte[] hash = new byte[28];

            sha3Shared.GetCurrentState(hash, 0, 28);

            return hash;
        }

        protected override byte[] GetPadding()
        {
            return sha3Shared.SHA3_GetLastBlockWithPad_HashFunction(CurrentMessageLengthWithoutPadding);
        }

        public override void ResetState()
        {
            sha3Shared.ResetState();
            base.ResetState();
        }
    }
}
