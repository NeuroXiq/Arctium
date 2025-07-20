using Arctium.Cryptography.Ciphers.Exceptions;

namespace Arctium.Cryptography.Ciphers.Helpers
{
    /// <summary>
    /// Common 
    /// </summary>
    public class CiphersValidation
    {
        public static void ThrowIfInvalidKeyLength(string algorithmName , int[] possibleKeyLength, int currentKeyLength)
        {
            bool ok = false;
            foreach (var len in possibleKeyLength)
            {
                if (len == currentKeyLength)
                {
                    ok = true;
                    break;
                }
            }

            if (!ok)
            {
                string keyLengths = "";
                for (int i = 0; i < possibleKeyLength.Length - 1; i++)
                {
                    keyLengths += possibleKeyLength[i].ToString() + ", ";
                }

                keyLengths += possibleKeyLength[possibleKeyLength.Length - 1].ToString();

                string message = $"$Valid key length for { algorithmName } : { keyLengths} but current value is: " + currentKeyLength;

                throw new InvalidKeyLengthException(message);
            }
        }

        public static void ThrowIfBlockLengthNotDivisible(string cipherName, long currentLength, long blockLength)
        {
            if (blockLength % currentLength != 0)
            {
                string message = $"{cipherName}: Invalid length of the input block. Current length: {currentLength} " +
                    $"but expected to be multiply of{blockLength}";
                throw new InvalidBlockLengthException(message);
            }
        }
    }
}
