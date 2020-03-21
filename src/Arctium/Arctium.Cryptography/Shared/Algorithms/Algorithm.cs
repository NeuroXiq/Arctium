namespace Arctium.Cryptography.Shared.Algorithms
{
    public enum Algorithm
    {
        // signature
        DSA,
        ECDSA,

        //ciphers asymmetric
        RSA,
        

        // Ciphers symmetric

        ChaCha20,

        // Hash
        MD2,
        MD5,
        SHA1,
        SHA2_224,
        SHA2_256,
        SHA2_512,
        SHA3_224,
        SHA3_256,
        SHA3_512,
    }
}
