using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.Exceptions;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.ASN1.Standards.X509.Model;

using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    class AuthorityKeyIdentifierDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            // all fields optional
            byte[] data = model.ExtnValue;

            DerDecoded decoded = DerDeserializer.Deserialize(data, 0);
            DerTypeDecoder decoder = new DerTypeDecoder(data);

            byte[] keyIdentifier = null;
            GeneralName[] generalNames = null;
            byte[] certSerialNum = null;

            int next = 0;

            // TODO X509/ExtensionDecoder order of items can be incorrect.
            // e.g. context-specific node [2] can be before context-specific node [1]
            // create validator for X690 for decoded node in X690 folder

            //all implicit tags

            long prev = -1;
            bool[] exists = new bool[3];
            DerDecoded[] values = new DerDecoded[3];
            foreach (var d in decoded)
            {
                long current = d.Tag.Number;
                if (prev < current)
                {
                    prev = current;
                    exists[current] = true;
                    values[current] = d;
                }
                else
                {
                    throw new X690DecoderException("invalid constructed type of authoritykeyidentifier");
                }
            }


            if (exists[0])
            {
                var keyIdentNode = values[0];
                keyIdentifier = decoder.OctetString(keyIdentNode);
            }
            if (exists[1])
            {
                generalNames = ExtensionsDecoder.DecodeGeneralNames(decoder, values[1]);
            }
            if (exists[2])
            {
                certSerialNum = decoder.Integer(decoded).BinaryValue;
            }

            return new AuthorityKeyIdentifierExtension(model.Critical.Value, generalNames, keyIdentifier, certSerialNum);

        }
    }
}
