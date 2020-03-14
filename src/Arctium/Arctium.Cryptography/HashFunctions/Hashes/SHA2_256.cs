using Arctium.DllGlobalShared.Helpers.Binary;
using System;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    public class SHA2_256 : HashFunctionBase
    {
        readonly uint[] InitialHashValue = new uint[]
        {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        };

        uint[] currentHashValue;
        uint[] messageScheduleBuffer;

        public SHA2_256() : base(512, 256)
        {
            currentHashValue = GetInitialHashValue();
            messageScheduleBuffer = new uint[64];
        }

        private uint[] GetInitialHashValue()
        {
            uint[] initalValue = new uint[InitialHashValue.Length];

            for (int i = 0; i < InitialHashValue.Length; i++)
            {
                initalValue[i] = InitialHashValue[i];
            }

            return initalValue;
        }

        protected override void ExecuteHashing(byte[] buffer, long offset, long length)
        {
            SHA2_224_256_Shared.PerformHashComputation(buffer, offset, length, currentHashValue, messageScheduleBuffer);
        }

        protected override byte[] GetCurrentHash()
        {
            byte[] hash = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                BinConverter.GetBytesBE(hash, i * 4, currentHashValue[i]);
            }

            return hash;
        }

        protected override byte[] GetPadding()
        {
            long totalMessageLength = base.CurrentMessageLength;
            return SHA2_224_256_Shared.GetPadding(totalMessageLength);
        }

        protected override void ResetCurrentState()
        {
            currentHashValue = GetInitialHashValue();
        }
    }
}
