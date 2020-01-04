using Arctium.Cryptography.CryptoHelpers;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    public class SHA2_384 : HashFunctionBase
    {
        static readonly ulong[] InitialHashValue = new ulong[] 
        {
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4
        };

        ulong[] hashValue;
        ulong[] messageScheduleBuffer;

        public SHA2_384() : base(1024, 384)
        {
            hashValue = GetInitialHashValue();
            messageScheduleBuffer = new ulong[80];
        }

        private ulong[] GetInitialHashValue()
        {
            ulong[] initial = new ulong[8];
            InitialHashValue.CopyTo(initial, 0);

            return initial;
        }

        protected override void ExecuteHashing(byte[] buffer, int offset, int length)
        {
            SHA2_384_512_Shared.PerformHashComputation(hashValue, buffer, offset, length, messageScheduleBuffer);
        }

        protected override byte[] GetCurrentHash()
        {
            byte[] result = new byte[48];

            for (int i = 0; i < 6; i++)
            {
                BinOps.ULongToBigEndianBytes(result, i * 8, hashValue[i]);
            }

            return result;
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
