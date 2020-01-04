using Arctium.Cryptography.CryptoHelpers;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    public class SHA2_512 : HashFunctionBase
    {
        static readonly ulong[] InitialHashValue = new ulong[]
        {
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        };

        ulong[] messageScheduleBuffer;
        ulong[] hashValue;

        public SHA2_512() : base(1024, 512)
        {
            messageScheduleBuffer = new ulong[80];
            hashValue = GetInitialHashValue();
        }

        private ulong[] GetInitialHashValue()
        {
            ulong[] init = new ulong[8];
            InitialHashValue.CopyTo(init, 0);

            return init;
        }

        protected override void ExecuteHashing(byte[] buffer, int offset, int length)
        {
            SHA2_384_512_Shared.PerformHashComputation(hashValue, buffer, offset, length, messageScheduleBuffer);
        }

        protected override byte[] GetCurrentHash()
        {
            byte[] hash = new byte[64];
            for (int i = 0; i < 8; i++)
            {
                BinOps.ULongToBigEndianBytes(hash, i * 8, hashValue[i]);
            }

            return hash;
        }

        protected override byte[] GetPadding()
        {
            return SHA2_384_512_Shared.GetPadding(CurrentMessageLength);
        }

        protected override void ResetCurrentState()
        {
            hashValue = GetInitialHashValue();
        }
    }
}
