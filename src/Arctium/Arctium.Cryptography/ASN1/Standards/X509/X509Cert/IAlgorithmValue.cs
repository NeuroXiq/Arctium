namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public interface IAlgorithmValue<T>
    {
        T ValueType { get; }
    }
}
