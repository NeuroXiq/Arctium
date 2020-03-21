using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.NodeDecoders.X690NodeDecoders;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders
{
    public class X509CertificateModelNodeDecoder : IX690NodeDecoder<X509CertificateModel>
    {
        TBSCertificateNodeDecoder tbsDecoder = new TBSCertificateNodeDecoder();
        AlgorithmIdentifierModelNodeDecoder algoIdDecoder = new AlgorithmIdentifierModelNodeDecoder();

        public X509CertificateModel Decode(X690DecodedNode node)
        {
            TBSCertificate tbsCert = tbsDecoder.Decode(node[0]);
            AlgorithmIdentifierModel algoId = algoIdDecoder.Decode(node[1]);
            BitString signatureValue = DerDecoders.DecodeWithTag<BitString>(node[2]).Value;

            X509CertificateModel model = new X509CertificateModel(tbsCert, algoId, signatureValue);
            return model;
        }
    }
}
