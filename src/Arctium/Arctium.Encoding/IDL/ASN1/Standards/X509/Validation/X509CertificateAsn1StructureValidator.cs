using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using System.Collections.Generic;
using static Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.Asn1TaggedTypeHelper;
namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Validation
{
    class X509CertificateAsn1StructureValidator
    {
        public X509StructureValidationResult ValidateStructure(List<Asn1TaggedType> rootContainer)
        {
            // TODO implement this
            return new X509StructureValidationResult() { Success = true };
        }
    }
}
/*Tag[] expected = new Tag[] { BuildInTag.Sequence, BuildInTag.Sequence, BuildInTag.Bitstring };
 if (rootDecodingContainer == null) throw new Asn1InternalException("input cannot be null", "", this);
            if (rootDecodingContainer.Count != 1) throw new X509FormatException(
                "Decooding result must consist of " +
                "a single sequence object but current decoding result do not match this restriction", rootDecodingContainer);


     if (HaveOrderedExactShallow(root, expected))
            {
                
            }
            else
            {
                Throw("Mandatory 2x sequence +  types not found on a top level of a decoded data");
            }s
     */
