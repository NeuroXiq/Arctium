using Arctium.Cryptography.HashFunctions.Hashes;

namespace Arctium.Cryptography.HashFunctions.XOF
{
    public class SHAKE256 : XOFBase
    {
        const int R_SpongeParam = 1600 - 512;
        const int OutputSizeInBits = R_SpongeParam;
        const int OutputSizeInBytes = OutputSizeInBits / 8;

        SHA3_Shared sha3Shared;

        public SHAKE256() : base(R_SpongeParam, R_SpongeParam)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
        }

        public override void GenerateNextOutputBytes(byte[] buffer, long offset)
        {
            sha3Shared.GetCurrentState(buffer, offset, OutputSizeInBytes);
            sha3Shared.Shake_GenerateNextState();
        }

        protected override void Feed(byte[] buffer, long offset, long length)
        {
            sha3Shared.MainHashComputation(buffer, offset, length);
        }

        protected override byte[] GetPadding()
        {
            return sha3Shared.SHA3_GetLastBlockWidthPad_ShakeFunctions(base.FeedBytesCount);
        }

        protected override void ResetState()
        {
            sha3Shared.ResetState();
        }
    }
}
