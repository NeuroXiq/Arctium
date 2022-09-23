using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.Ciphers.BlockCiphers.ModeOfOperation;
using Arctium.Shared.Other;

namespace Arctium.Standards.Crypto
{
    public class AEAD_Predefined
    {
        /// <summary>
        /// Creates new instance of AEAD_AES_128_CCM
        /// the nonce length n is 12,
        /// the tag length t is 16, and
        /// the value of q is 3.
        /// Equivalent to calling <see cref="Arctium.Cryptography.Ciphers.BlockCiphers.ModeOfOperation.CCMMode"/>
        /// </summary>
        /// <returns></returns>
        public static AEAD Create_AEAD_AES_128_CCM(byte[] aesKey)
        {
            Validation.Length(aesKey, 16, nameof(aesKey));
            return new CCMMode(new AES(aesKey), 16);
        }

        /// <summary>
        /// rfc6655
        /// </summary>
        /// <returns></returns>
        public static AEAD Create_AEAD_AES_128_CCM_8(byte[] aesKey)
        {
            Validation.Length(aesKey, 16, nameof(aesKey));

            return new CCMMode(new AES(aesKey), 8);
        }
    }
}
