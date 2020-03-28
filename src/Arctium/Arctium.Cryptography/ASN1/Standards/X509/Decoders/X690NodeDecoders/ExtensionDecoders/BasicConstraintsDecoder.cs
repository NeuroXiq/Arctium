using System;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using ASN = Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class BasicConstraintsDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();
        X690Validation valid = new X690Validation(nameof(BasicConstraintsDecoder));
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            X690DecodedNode bcSequence = derDeserializer.Deserialize(model.ExtnValue.Value)[0];

            if (bcSequence.ConstructedCount == 0)
                return new BasicConstraintsExtension(false, model.Critical);

            valid.MinMax(bcSequence, 1, 2);

            int next = 0;
            bool ca = false;
            int pathLen = -1;
            bool pathLenPresent = false;

            if (bcSequence[0].TagEqual(BuildInTag.Boolean))
            {
                ca = DerDecoders.DecodeWithoutTag<ASN.Boolean>(bcSequence[0]);
                next++;
            }
            if (bcSequence[next].TagEqual(BuildInTag.Integer))
            {
                uint integer = DerDecoders.DecodeWithoutTag<Integer>(bcSequence[1]);
                checked
                {
                    pathLen = (int)integer;
                }
                pathLenPresent = true;
                next++;
            }

            // not processed some tags, something is invalid with tags
            if (next != bcSequence.ConstructedCount)
                throw new X509DecodingException(
                    "Fields in BasicConstraints extensions" + 
                    " are invalid. Some tag(s) are unrecognized");

            if (pathLenPresent)
            {
                return new BasicConstraintsExtension(ca, pathLen, model.Critical);
            }
            else
            {
                return new BasicConstraintsExtension(ca, model.Critical);
            }
        }
    }
}
