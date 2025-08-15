using Arctium.Shared;
using System;

namespace Arctium.Cryptography.HashFunctions.CRC
{
    public class CRC8 : CRC<byte>
    {
        public CRC8(byte polynomial,
            byte initialValue,
            bool inputReflected,
            bool resultReflected,
            byte finalXorValue) : this(null,
                polynomial,
                initialValue,
                finalXorValue,
                inputReflected,
                resultReflected)
        {
        }

        public CRC8(string name, 
            byte polynomial,
            byte initialValue,
            byte finalXorValue,
            bool inputReflected,
            bool resultReflected)
            : base(name,
                polynomial,
                initialValue,
                finalXorValue,
                inputReflected,
                resultReflected)
        {
            SetLookupTable();
        }

        private void SetLookupTable()
        {
            lookupTable = new byte[256];
            byte result = 0;

            for (int i = 0; i < 256; i++)
            {
                byte num = (byte)i;

                for (int j = 0; j < 8; j++)
                {
                    if ((num & 0x80) != 0)
                    {
                        result ^= (byte)(Polynomial << (7 - j));
                        num = (byte)((num) ^ (Polynomial >> 1));
                    }
                    num <<= 1;
                }

                lookupTable[i] = result;
                result = 0;
            }
        }

        public override byte Result()
        {
            byte res = InputReflected ? BinOps.BitReflect(currentValue) : currentValue;

            return (byte)(res ^ FinalXorValue);
        }

        protected override void ProcessByte(byte b)
        {
            byte r = (byte)(b ^ currentValue);
            byte lookup = lookupTable[r];

            currentValue = lookup;
        }
    }
}
