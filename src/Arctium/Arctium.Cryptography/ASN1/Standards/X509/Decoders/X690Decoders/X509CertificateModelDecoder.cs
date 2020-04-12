using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690v2.DER;
using Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.NodeDecoders.X690NodeDecoders;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690Decoders
{
    public class X509CertificateModelDecoder
    {
        TBSCertificateDecoder tbsDecoder = new TBSCertificateDecoder();
        AlgorithmIdentifierModelDecoder algoIdDecoder = new AlgorithmIdentifierModelDecoder();

        public X509CertificateModel Decode(DerTypeDecoder decoder, DerDecoded certRootSequence)
        {
            TBSCertificate tbsCert = tbsDecoder.Decode(decoder, certRootSequence[0]);
            AlgorithmIdentifierModel algoId = algoIdDecoder.Decode(decoder, certRootSequence[1]);
            BitString signatureValue = decoder.BitString(certRootSequence[2]);

            X509CertificateModel model = new X509CertificateModel(tbsCert, algoId, signatureValue);
            return model;
        }
    }
}
