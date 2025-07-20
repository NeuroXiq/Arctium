namespace Arctium.Cryptography.Shared.Algorithms
{
    public struct SignatureAlgorithmPair
    {
        public Algorithm Hash;
        public Algorithm Crypto;

        public SignatureAlgorithmPair(Algorithm hash, Algorithm crypto)
        {
            Hash = hash;
            Crypto = crypto;
        }
    }
}
