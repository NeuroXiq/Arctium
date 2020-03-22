using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class KeyUsageDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();
        public CertificateExtension DecodeExtension(ExtensionModel arg)
        {
            var node = derDeserializer.Deserialize(arg.ExtnValue)[0];
            BitString flagsBitstring = DerDecoders.DecodeWithoutTag<BitString>(node);

            KeyUsageExtension.KeyUsageFlags flags = DecodeKeyUsageFlags(flagsBitstring);

            return new KeyUsageExtension(arg.Critical, flags);
        }

        /// <summary>
        /// Converts raw bitstring value of the KeyUsageExtension to <see cref="KeyUsageExtension.KeyUsageFlags"/> structure
        /// </summary>
        /// <param name="bitstring">Encoded key usage flags BitString</param>
        /// <returns>Decoded <see cref="KeyUsageExtension.KeyUsageFlags"/> structure </returns>
        public static KeyUsageExtension.KeyUsageFlags DecodeKeyUsageFlags(BitString bitstring)
        {
            if (bitstring.Length > 9)
                throw new X590DecodingException("Invalid coding of the KeyUsageExtension.KeyUsageFlags BitString value. LEngth must be in range 0-9");

            byte flags0 = bitstring.Value[0];


            if (bitstring.Length <= 8)
            {
                for (int i = 0; i < (8 - bitstring.Length); i++)
                {
                    // clear unused bits to be sure that all of them are off
                    flags0 &= (byte)(~(1 << i));
                }
            }

            KeyUsageExtension.KeyUsageFlags usageFlags = new KeyUsageExtension.KeyUsageFlags();

            usageFlags.DigitalSignature = (flags0 & (1 << 7)) > 0;
            usageFlags.NonRepudiation = (flags0 & (1 << 6)) > 0;
            usageFlags.KeyEncipherment = (flags0 & (1 << 5)) > 0;
            usageFlags.DataEncipherment = (flags0 & (1 << 4)) > 0;
            usageFlags.KeyAgreement = (flags0 & (1 << 3)) > 0;
            usageFlags.KeyCertSign = (flags0 & (1 << 2)) > 0;
            usageFlags.CRLSign = (flags0 & (1 << 1)) > 0;
            usageFlags.EncipherOnly = (flags0 & (1 << 0)) > 0;
            usageFlags.DecipherOnly = false;

            if (bitstring.Length > 8) usageFlags.DecipherOnly = (flags0 & (1 << 7)) > 0;

            return usageFlags;
        }

    }
}
