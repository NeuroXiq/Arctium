using Arctium.Shared;
using System.Numerics;

namespace Arctium.Cryptography.Ciphers.DiffieHellman.Algorithms
{
    internal class FFDHEAlgorithm
    {
        public static void GeneratePrivateAndPublicKey(FFDHEParams parms, out byte[] privateKey, out byte[] publicKeyToSendToOtherParty)
        {
            long groupLenInBytes = (parms.P.GetBitLength() + 7) / 8;

            privateKey = new byte[groupLenInBytes];

            do
            {
                GlobalConfig.RandomGeneratorCryptSecure(privateKey, 0, privateKey.Length);
            } while (privateKey[0] == 0);

            BigInteger privKeyInt = new BigInteger(privateKey, true, true);
            BigInteger publicKeyInt = BigInteger.ModPow(parms.G, privKeyInt, parms.P);

            byte[] publicKey = new byte[groupLenInBytes];
            byte[] pubKeyIntAsBytes = publicKeyInt.ToByteArray(true, true);

            // do not truncate zeros
            MemCpy.Copy(pubKeyIntAsBytes, 0, publicKey, groupLenInBytes - pubKeyIntAsBytes.Length, pubKeyIntAsBytes.Length);

            publicKeyToSendToOtherParty = publicKey;
        }

        public static byte[] ComputeSharedSecret(FFDHEParams parms, byte[] privateKey, byte[] otherPartyPublicKey)
        {
            long groupLenBytes = (parms.P.GetBitLength() + 7) / 8;

            Validation.Length(otherPartyPublicKey.Length, groupLenBytes, nameof(otherPartyPublicKey), "publicKey len invalid, leading zeros shoud not be truncated");
            Validation.Length(privateKey, groupLenBytes, nameof(privateKey), "invalid priv key, leading zero must not be truncated");

            BigInteger privKeyInt = new BigInteger(privateKey, true, true);
            BigInteger otherPartyInt = new BigInteger(otherPartyPublicKey, true, true);
            BigInteger sharedSecret = BigInteger.ModPow(otherPartyInt, privKeyInt, parms.P);

            byte[] sharedSecretBytes = new byte[groupLenBytes];
            byte[] sharedSecretTruncated = sharedSecret.ToByteArray(true, true);

            // do not truncate zeros
            MemCpy.Copy(sharedSecretTruncated, 0, sharedSecretBytes, groupLenBytes - sharedSecretTruncated.Length, sharedSecretTruncated.Length);

            return sharedSecretBytes;
        }
    }
}
