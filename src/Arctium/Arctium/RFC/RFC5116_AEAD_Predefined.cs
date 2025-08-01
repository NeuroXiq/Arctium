using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.Ciphers.BlockCiphers.ModeOfOperation;
using Arctium.Shared;

namespace Arctium.Standards.RFC
{
    /// <summary>
    /// Predefined values for AEAD ciphers (method sets valid Authentication tag length).
    /// 
    /// https://www.rfc-editor.org/rfc/rfc5116.txt
    /// Network Working Group                                          D. McGrew
    /// Request for Comments: 5116                           Cisco Systems, Inc.
    /// Category: Standards Track                                   January 2008
    ///
    /// 
    /// An Interface and Algorithms for Authenticated Encryption
    /// </summary>
    public class RFC5116_AEAD_Predefined
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
        ///  This algorithm is identical to AEAD_AES_128_GCM, but with the
        /// following differences:
        /// K_LEN is 32 octets, instead of 16 octets, and
        /// AES-256 GCM is used instead of AES-128 GCM.
        /// </summary>
        /// <param name="aesKey"></param>
        /// <returns></returns>
        public static AEAD Create_AEAD_AES_256_GCM(byte[] aesKey)
        {
            Validation.Length(aesKey, 32, nameof(aesKey));
            return new GaloisCounterMode(new AES(aesKey), 16);
        }

        public static AEAD Create_AEAD_AES_256_CCM(byte[] aesKey)
        {
            Validation.Length(aesKey, 32, nameof(aesKey));
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
