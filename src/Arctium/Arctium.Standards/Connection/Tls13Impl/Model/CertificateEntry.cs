using Arctium.Standards.Connection.Tls13Impl.Model.Extensions;

namespace Arctium.Standards.Connection.Tls13Impl.Model
{
    internal class CertificateEntry
    {
        public CertificateType? CertificateType { get; private set; }

        public byte[] CertificateEntryRawBytes { get; private set; }

        // public byte[] SubjectPublicKeyInfo { get; private set; }
        // 
        // public byte[] CertData { get; private set; }

        public Extension[] Extensions { get; private set; }

        public CertificateEntry(CertificateType? type, byte[] bytes, Extension[] extensions)
        {
            Extensions = extensions;

            CertificateEntryRawBytes = bytes;

            // switch (type)
            // {
            //     case CertificateType.X509: CertData = bytes; break;
            //     case CertificateType.RawPublicKey: SubjectPublicKeyInfo = bytes; break;
            //     default: throw new System.ArgumentException("type");
            // }
        }
    }
}