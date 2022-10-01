using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;

namespace Arctium.Standards.Connection.Tls.Tls13.Model
{
    internal class CertificateRequest
    {
        public byte[] CertificateRequestContext { get; private set; }
        public Extension[] Extensions { get; private set; }

        public CertificateRequest(byte[] certificateRequestContext, Extension[] extensions)
        {
            CertificateRequestContext = certificateRequestContext;
            Extensions = extensions;
        }
    }
}
