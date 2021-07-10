using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;

namespace Arctium.Cryptography.HashFunctions.XOF
{

    public class SHAKE128 : XOFBase
    {
        const int R_SpongeParam = (1600 - 256);
        const int OutputSizeInBits = R_SpongeParam;
        const int OutputSizeInBytes = OutputSizeInBits / 8;

        SHA3_Shared sha3Shared;

        public SHAKE128() : base(OutputSizeInBits, R_SpongeParam)
        {
            sha3Shared = new SHA3_Shared(R_SpongeParam);
        }

        protected unsafe override void Feed(byte[] buffer, long offset, long length)
        {
            fixed (byte* input = &buffer[offset])
            {
                sha3Shared.MainHashComputation(input, length);
            }
        }

        public override void GenerateNextOutputBytes(byte[] buffer, long offset)
        {
            sha3Shared.GetCurrentState(buffer, offset, OutputSizeInBytes);
            sha3Shared.Shake_GenerateNextState();
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
