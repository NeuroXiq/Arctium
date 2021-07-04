*NOT-FINISHED/NOT-WORKING*

Dev overview: 

Directy info:
**Decoders/X690Nodes../**: Cefinitions for DER  encoded structures,
extensions decoders are located in subdir 'extensionDecoders'

**Mapping**: Contains mapping from CertificateModel to X509Certificate object

**Mapping/OID**: Contains static classes which maps ObjectIdentifies (1.2.3.4.5 ... etc.)
to Enumerated types/constant values etc (mapping are bidirectional,
from enum/const to OID and reverse).
**Model**:  contains classes of 'models' used in this namespace

**X509Cert**:  This is a final area where ready-to-work certificate entities are located. 

What is 'model' class :
'Model' classes are something between final class ready-to-use and from X690 DER
decoded structure (X690DecodedNode). 'Models' of the extensions and certificate are
always valid, but contains mixed values, e.g. some raw bytes arrays with encoded data,
ASN1 types like BitString etc. Model classes exists for sake of simplicity of
encoding/decoding strucutres. More easy is to encode/decode classes, where fields
are low-level (bytes, octetstring etc.) final-class classes (X509Cert directory) are 
(or will be/shoul be) fully mapped to OOP structures like enums/class/struct/interface etc.
final-class do not (or shall not) contains decoding artifacts like bitstring, octetstring etc. 

**Mapping/X509CertificateMapper** performs mapping from 'model' certificate to 'final' certificate.
Extensions are most important, 'extension model' consists of raw-bytes of the inner extension.
'mappers-decoders' for extensions are located in: decoders/x690.../extensiondecoders

look at:
decoders/x690.../extensiondecoders/extensiondecoder.cs
