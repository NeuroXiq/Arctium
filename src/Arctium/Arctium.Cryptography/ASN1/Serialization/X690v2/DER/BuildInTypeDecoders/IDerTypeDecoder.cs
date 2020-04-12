namespace Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public interface IDerTypeDecoder<T>
    {
        T Decode(byte[] buffer, long offset, long contentLength);
    }
}
