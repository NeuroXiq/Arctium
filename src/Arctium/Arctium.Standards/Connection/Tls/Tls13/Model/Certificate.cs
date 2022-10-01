using Arctium.Standards.Connection.Tls.Tls13.Model;

namespace Arctium.Standards.Connection.Tls.Tls13.Model
{
    internal class Certificate
    {
        public byte[] CertificateRequestContext { get; private set; }
        public CertificateEntry[] CertificateList { get; private set; }

        public Certificate(byte[] certificateRequestContext, CertificateEntry[] certificateList)
        {
            CertificateRequestContext = certificateRequestContext;
            CertificateList = certificateList;
        }   

    }

}