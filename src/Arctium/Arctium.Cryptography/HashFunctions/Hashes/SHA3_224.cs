namespace Arctium.Cryptography.HashFunctions.Hashes
{
    public class SHA3_224 : HashFunctionBase
    {
        const int R_SpongeParam = 1600 - 448;

        readonly SHA3_Shared sha3Shared;

        public SHA3_224() : base(R_SpongeParam, 224)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
        }

        protected override void ExecuteHashing(byte[] buffer, long offset, long length)
        {
            sha3Shared.MainHashComputation(buffer, offset, length);
        }

        protected override byte[] GetCurrentHash()
        {
            return sha3Shared.GetHashFromState(224);
        }

        protected override byte[] GetPadding()
        {
            return sha3Shared.SHA3_GetLastBlockWithPadForHashFunction(CurrentMessageLength);
        }

        protected override void ResetCurrentState()
        {
            sha3Shared.ResetState();
        }
    }
}
