namespace Arctium.Cryptography.HashFunctions.FunctionAlgorithms.Keccak
{
    /// <summary>
    /// Permutation width of the Keccak algorithm.
    /// </summary>
    public enum PWidth : int
    {
        /// <summary>
        /// Represents 25 bit length permutation.
        /// </summary>
        P25 = 25,
        /// <summary>
        /// Represents 50 bit length permutation.
        /// </summary>
        P50 = 50,
        /// <summary>
        /// Represents 100 bit length permutation.
        /// </summary>
        P100 = 100,
        /// <summary>
        /// Represents 200 bit length permutation.
        /// </summary>
        P200 = 200,
        /// <summary>
        /// Represents 400 bit length permutation.
        /// </summary>
        P400 = 400,
        /// <summary>
        /// Represents 800 bit length permutation.
        /// </summary>
        P800 = 800,
        /// <summary>
        /// Represents 1600 bit length permutation.
        /// </summary>
        P1600 = 1600
    }
}
