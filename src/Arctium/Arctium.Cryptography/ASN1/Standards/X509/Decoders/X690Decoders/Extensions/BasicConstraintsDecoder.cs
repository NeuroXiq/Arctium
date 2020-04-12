using System;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using ASN = Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    class BasicConstraintsDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();
        X690Validation valid = new X690Validation(nameof(BasicConstraintsDecoder));
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            X690DecodedNode bcSequence = derDeserializer.Deserialize(model.ExtnValue.Value)[0];
            int count = bcSequence.ConstructedCount;

            if (count == 0)
                return new BasicConstraintsExtension(false, model.Critical);

            valid.MinMax(bcSequence, 1, 2);

            bool ca = false;
            bool pathLenPresent = false;
            int pathLen = -1;

            if (count == 1)
            {
                if (bcSequence[0].TagEqual(BuildInTag.Boolean))
                {
                    ca = DerDecoders.DecodeWithoutTag<ASN.Boolean>(bcSequence[0]);
                }
                else
                {
                    pathLenPresent = true;
                    checked
                    {
                        pathLen = (int)DerDecoders.DecodeWithoutTag<Integer>(bcSequence[0]);
                    }
                }

            }
            else
            {
                pathLenPresent = true;
                ca = DerDecoders.DecodeWithoutTag<ASN.Boolean>(bcSequence[0]);
                checked
                {
                    pathLen = (int)DerDecoders.DecodeWithoutTag<Integer>(bcSequence[0]);
                }
            }


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
