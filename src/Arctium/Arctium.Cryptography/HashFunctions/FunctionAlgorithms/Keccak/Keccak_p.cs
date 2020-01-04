using System;

namespace Arctium.Cryptography.HashFunctions.FunctionAlgorithms.Keccak
{
    /// <summary>
    /// Keccak-p instance defined in FIPS PUB 202 generalization of Keccak-f where number of round is an input parameter.
    /// </summary>
    public class Keccak_p
    {
        /// <summary>
        /// Permutation width, 'b' parameter.
        /// </summary>
        public int PermutationWidth { get; private set; }

        /// <summary>
        /// Count of the 25-bit slices of the state array. Indicated by 'w' parameter
        /// </summary>
        public int StateArrayDepth { get; private set; }


        /// <summary>
        /// Log2 of the state array depth <seealso cref="StateArrayDepth"/>
        /// </summary>
        public int StateArrayDepthLog { get; private set; }

        /// <summary>
        /// Number of rounds.
        /// </summary>
        public int NumberOfRounds { get; private set; }



        public int b { get; private set; }
        
        /// <summary>
        /// Quantity related to <see cref="PWidth"/> equal to:  PWidth / 25. 
        /// </summary>
        public int w { get; private set; }

        /// <summary>
        /// Quantity related to <see cref="PWidth"/> equal to:  log2(<see cref="PermutationWidth"/>/25)
        /// </summary>
        public int l { get; private set; }



        public Keccak_p(PWidth permutationWidth ,int numberOfRounds)
        {
            b = (int)permutationWidth;
            w = PermutationWidth / 25;
            l = (int)Math.Log(w, 2);

            PermutationWidth = b;
            StateArrayDepth = w;
            StateArrayDepthLog = l;

            NumberOfRounds = numberOfRounds;
        }
    }
}
