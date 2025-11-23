namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// experimental
    /// </summary>
    public class RDataNULL
    {
        public byte[] Anything;

        public RDataNULL() { }
        public RDataNULL(byte[] anything) { Anything = anything; }
    }
}
