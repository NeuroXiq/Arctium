using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using static Arctium.Cryptography.ASN1.Standards.X509.X509Cert.SignatureAlgorithm;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping
{
    /*
     * -class info-
     * Creates object representation of encoded  
     * signature params/values 
     */


    public class SignatureMapper
    {
        HashSet<SignatureAlgorithm> parmsMustBeNull = new HashSet<SignatureAlgorithm>()
        {
            SHA224WithRSAEncryption, SHA384WithRSAEncryption, SHA512WithRSAEncryption, SHA256WithRSAEncryption,
            MD2WithRSAEncryption, MD5WithRSAEncryption,
        };


        internal Signature Map(AlgorithmIdentifierModel signature, BitString signatureValue)
        {
            SignatureAlgorithm algorithmType = SignatureAlgorithmOidMap.Get(signature.Algorithm);
            object parms = MapParameters(algorithmType, signature.EncodedParameters);

            return new Signature(algorithmType, parms, signatureValue.Value);
        }

        private object MapParameters(SignatureAlgorithm algorithmType, byte[] encodedParameters)
        {
            if (parmsMustBeNull.Contains(algorithmType))
            {
                if (encodedParameters != null)
                    throw new X509DecodingException(
                        $"{nameof(SignatureMapper)}" +
                        "Parameters value must be null but current value is not null." +
                        $"AlgorithmType: {algorithmType}");

                return null;
            }

            throw new NotSupportedException($"signaturemapper not supports {algorithmType}");
        }
    }
}
