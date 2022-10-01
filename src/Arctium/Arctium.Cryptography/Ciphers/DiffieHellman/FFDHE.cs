using Arctium.Cryptography.Ciphers.DiffieHellman.Algorithms;

namespace Arctium.Cryptography.Ciphers.DiffieHellman
{
    public class FFDHE
    {
        public static void GeneratePrivateAndPublicKey(FFDHEParams parms, out byte[] privateKey, out byte[] publicKeyToSendToOtherParty)
        {
            FFDHEAlgorithm.GeneratePrivateAndPublicKey(parms, out privateKey, out publicKeyToSendToOtherParty);
        }

        public static byte[] ComputeSharedSecret(FFDHEParams parms, byte[] privateKey, byte[] otherPartyPublicKey)
        {
            return FFDHEAlgorithm.ComputeSharedSecret(parms, privateKey, otherPartyPublicKey);
        }
    }
}
