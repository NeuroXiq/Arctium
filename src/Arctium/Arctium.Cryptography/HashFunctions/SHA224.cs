﻿using Arctium.Cryptography.CryptoHelpers;
using System;

namespace Arctium.Cryptography.HashFunctions
{
    public class SHA224 : HashFunctionBase
    {
        uint[] InitialHashValue = new uint[]
        {
            0xc1059ed8,
            0x367cd507,
            0x3070dd17,
            0xf70e5939,
            0xffc00b31,
            0x68581511,
            0x64f98fa7,
            0xbefa4fa4
        };

        //represents eigth 32-bit words
        uint[] hashValue;

        uint[] messageScheduleBuffer;

        public SHA224() : base(512, 224)
        {
            hashValue = GetInitialHashValue();
            messageScheduleBuffer = new uint[64];
        }

        protected override void ExecuteHashing(byte[] buffer, int offset, int length)
        {
            SHA224_256_Shared.PerformHashComputation(buffer, offset, length, hashValue, messageScheduleBuffer);
        }

        private uint[] GetInitialHashValue()
        {
            uint[] initialValue = new uint[InitialHashValue.Length];
            for (int i = 0; i < initialValue.Length; i++)
            {
                initialValue[i] = InitialHashValue[i];
            }

            return initialValue;
        }

        protected override byte[] GetPadding()
        {
            long totalMessageLength = hashedBytesCount + hashDataBuffer.DataLength;
            return SHA224_256_Shared.GetPadding(totalMessageLength);
        }

        public override void ResetState()
        {
            base.ResetState();
            hashValue = GetInitialHashValue();
        }

        protected override byte[] GetCurrentHash()
        {
            byte[] result = new byte[28];

            for (int i = 0; i < 7; i++)
            {
                BitOps.IntToBigEndianBytes(result, i * 4, hashValue[i]);
            }

            return result;
        }
    }
}
