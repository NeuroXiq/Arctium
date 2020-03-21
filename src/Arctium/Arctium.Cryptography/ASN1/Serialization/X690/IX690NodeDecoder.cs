namespace Arctium.Cryptography.ASN1.Serialization.X690
{
    public interface IX690NodeDecoder<T>
    {
        T Decode(X690DecodedNode node);
    }
}
