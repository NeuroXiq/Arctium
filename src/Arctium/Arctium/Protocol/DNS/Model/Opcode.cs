namespace Arctium.Protocol.DNS.Model
{
    public enum Opcode : byte
    {
        Query = 0,
        [Obsolete("obsoleted in rfc3425")]
        IQuery = 1,
        Status = 2,

        // other are reserved
    }
}
