using System;
using System.Collections.Generic;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Standards.X509.Exceptions;
using Arctium.Standards.ASN1.Standards.X509.Mapping.OID;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping
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
            SignatureAlgorithm.SHA1WithRSAEncryption,
            SignatureAlgorithm.SHA224WithRSAEncryption,
            SignatureAlgorithm.SHA384WithRSAEncryption,
            SignatureAlgorithm.SHA512WithRSAEncryption,
            SignatureAlgorithm.SHA256WithRSAEncryption,
            SignatureAlgorithm.MD2WithRSAEncryption,
            SignatureAlgorithm.MD5WithRSAEncryption,
            SignatureAlgorithm.ECDSAWithSHA224,
            SignatureAlgorithm.ECDSAWithSHA256,
            SignatureAlgorithm.ECDSAWithSHA384,
            SignatureAlgorithm.ECDSAWithSHA512,
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
