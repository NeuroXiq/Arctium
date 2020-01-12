//using System;

//namespace Arctium.Cryptography.HashFunctions.FunctionAlgorithms.Keccak
//{
//    /// <summary>
//    /// Keccak state array 'A'
//    /// </summary>
//    class StateArray
//    {
//        private bool[] state;
//        int w;

//        public StateArray(int w)
//        {
//            this.w = w;
//            state = new bool[w * 25];
//        }

        

//        public bool this[int x, int y, int z]
//        {
//            get
//            {
//                int index = (w * ((5 * y) + x)) + z;
//                return state[index];
//            }
//            set
//            {
//                int index = (w * ((5 * y) + x)) + z;
//                state[index] = value;
//            }
//        }


//        /// <summary>
//        /// Convert state to bit String represented as byte array.
//        /// </summary>
//        /// <returns></returns>
//        public byte[] ToByteArray()
//        {
//            int byteLength = w / 8;
//            //extend if some bits not fit
//            byteLength = (byteLength * 8) < w ? byteLength : byteLength + 1;

//            byte[] result = new byte[byteLength];

//            for (int x = 0; x < 5; x++)
//            {
//                for (int y = 0; y < 5; y++)
//                {
//                    for (int z = 0; z < w; z++)
//                    {
//                        int bitNo = (w * (5 * y) + x) + z;

//                        int byteNo = bitNo / 8;
//                        int bitInByte = bitNo % 8;

//                        byte stateBit = state[bitNo] ? (byte)1 : (byte)0;
//                        stateBit <<= bitInByte;

//                        result[byteNo] |= (byte)stateBit;
//                    }
//                }
//            }

//            return result;
//        }

//        /// <summary>
//        /// Need to transform 5 * 5 * 'w' bit string to some byte array.
//        /// Values may not be multiply of '8'
//        /// </summary>
//        /// <param name="w"></param>
//        /// <returns></returns>
//        private int GetStateLengthInBytes(int w)
//        {
//            int bitSize = w * 5 * 5;

//            int byteLen = bitSize / 8;

//            if (byteLen * 8 < bitSize) byteLen++;

//            return byteLen;
//        }

//    }
//}
