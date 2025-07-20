using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.ASN1.Standards.X509.NodeDecoders.X690NodeDecoders;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders
{
    public class X509CertificateModelDecoder
    {
        TBSCertificateDecoder tbsDecoder = new TBSCertificateDecoder();

        public X509CertificateModel Decode(DerDeserializedContext context)
        {
            context.Current = context.Root[0];
            TBSCertificate tbsCert = tbsDecoder.Decode(context);
            
            context.Current = context.Root[1];
            AlgorithmIdentifierModel algoId = AlgorithmIdentifierModelDecoder.Decode(context);

            context.Current = context.Root[2];
            BitString signatureValue = context.DerTypeDecoder.BitString(context.Current);

            X509CertificateModel model = new X509CertificateModel(tbsCert, algoId, signatureValue);
            return model;
        }
    }
}
