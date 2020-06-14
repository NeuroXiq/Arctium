using System;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public unsafe class SHA3_384 : HashFunctionBase
    {
        const int HashSizeInBits = 384;
        const int R_SpongeParam = 1600 - (2 * HashSizeInBits);

        SHA3_Shared sha3Shared;

        public SHA3_384() : base(R_SpongeParam, HashSizeInBits)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
        }

        protected override void ExecuteHashing(byte* buffer, long length)
        {
            sha3Shared.MainHashComputation(buffer, length);
        }

        protected override byte[] GetCurrentHash()
        {
            byte[] hash = new byte[48];

            sha3Shared.GetCurrentState(hash, 0, 48);

            return hash;
        }

        protected override byte[] GetPadding()
        {
            return sha3Shared.SHA3_GetLastBlockWithPad_HashFunction(base.CurrentMessageLengthWithoutPadding);
        }

        public override void ResetState()
        {
            sha3Shared.ResetState();
            base.ResetState();
        }
    }
}
