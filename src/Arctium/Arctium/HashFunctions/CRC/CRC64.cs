using Arctium.Shared;

namespace Arctium.Cryptography.HashFunctions.CRC
{
    public class CRC64 : CRC<ulong>
    {
        public CRC64(string name,
            ulong polynomial,
            ulong initialValue,
            ulong finalXorValue,
            bool inputReflected,
            bool resultReflected) : base(name, polynomial, initialValue, finalXorValue, inputReflected, resultReflected)
        {
            SetLookupTable();
        }

        private void SetLookupTable()
        {
            lookupTable = new ulong[256];

            for (int i = 0; i < 256; i++)
            {
                ulong result = 0;
                ulong value = (ulong)i << 55;
                ulong msbit = (ulong)((ulong)1 << 63);
                
                for (int j = 0; j < 8; j++)
                {
                    value <<= 1;

                    if ((value & msbit) != 0)
                    {
                        result ^= (Polynomial << (7 - j));
                        value = (value) ^ (Polynomial >> 1);
                    }
                }

                lookupTable[i] = result;
            }
        }

        public override ulong Result()
        {
            ulong resultAfterXor = currentValue ^ FinalXorValue;
            ulong final = ResultReflected ? BinOps.BitReflect(resultAfterXor) : resultAfterXor;

            return final;
        }

        protected override void ProcessByte(byte b)
        {
            int idx = (int)((((ulong)b << 56) ^ currentValue) >> 56);

            ulong v = lookupTable[idx];

            currentValue = (currentValue << 8) ^ v;
        }
    }
}
