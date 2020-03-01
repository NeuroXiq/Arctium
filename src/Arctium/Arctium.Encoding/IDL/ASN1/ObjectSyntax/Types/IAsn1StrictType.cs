namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types
{
    public interface IAsn1StrictType<T>
    {
        T TypedValue { get; set; }
        void SetAsStrict(object value);
    }
}
