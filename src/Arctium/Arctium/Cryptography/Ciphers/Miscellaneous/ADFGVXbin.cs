namespace Arctium.Cryptography.Ciphers.Miscellaneous
{
    public class ADFGVXbin
    {
        struct TranspositionTable
        {
            public int[] ToSortedIndex;

        }

        struct ValuesTableWithKey
        {
            public byte[] Values; 
        }

        byte[] key;

        public ADFGVXbin(byte[] key)
        {
            this.key = key;
        }


        public void Decrypt(byte[] buffer, int offset, int length)
        {

        }

        public void Encrypt(byte[] buffer, int offset, int length)
        {

        }


        private ValuesTableWithKey GetKeyedValuesTable(byte[] key)
        {
            bool[] containsValue = new bool[256];
            ValuesTableWithKey vtwk = new ValuesTableWithKey();
            byte[] values = new byte[256];

            //first copy key to table
            for (int i = 0; i < key.Length; i++)
            {
                values[i] = key[i];
                containsValue[key[i]] = true;
            }

            //
            // now insert all remaining values which key do not contain
            // table must contain all bytes (0 - 255)

            //first byte after key
            int insertIndex = key.Length;

            //insert remaining values which key do not contain
            for (int i = 0; i < 256 - key.Length; i++)
            {
                if (containsValue[i]) continue;

                values[insertIndex] = (byte)i;
                insertIndex++;
            }

            vtwk.Values = values;

            return vtwk;

        }
    }
}
