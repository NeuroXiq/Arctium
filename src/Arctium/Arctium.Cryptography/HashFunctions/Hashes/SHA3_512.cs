namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class SHA3_512 : HashFunctionBase
    {
        const int HashSizeInBits = 512;
        const int R_SpongeParam = 1600 - (2 * HashSizeInBits);

        SHA3_Shared sha3Shared;
        public SHA3_512() : base(R_SpongeParam, HashSizeInBits)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
        }

        protected override void ExecuteHashing(byte[] buffer, long offset, long length)
        {
            sha3Shared.MainHashComputation(buffer, offset, length);
        }

        protected override byte[] GetCurrentHash()
        {
            return sha3Shared.GetHashFromState(HashSizeInBits);
        }

        protected override byte[] GetPadding()
        {
            return sha3Shared.SHA3_GetLastBlockWithPadForHashFunction(base.CurrentMessageLength);
        }

        protected override void ResetCurrentState()
        {
            sha3Shared.ResetState();
        }
    }
}
