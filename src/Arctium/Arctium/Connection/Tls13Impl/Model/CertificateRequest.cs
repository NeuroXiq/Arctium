using Arctium.Standards.Connection.Tls13Impl.Model.Extensions;
using System.Collections.Generic;

namespace Arctium.Standards.Connection.Tls13Impl.Model
{
    internal class CertificateRequest
    {
        public byte[] CertificateRequestContext { get; private set; }
        public List<Extension> Extensions { get; private set; }

        public CertificateRequest(byte[] certificateRequestContext, Extension[] extensions)
        {
            CertificateRequestContext = certificateRequestContext;
            Extensions = new List<Extension>(extensions);
        }
    }
}
