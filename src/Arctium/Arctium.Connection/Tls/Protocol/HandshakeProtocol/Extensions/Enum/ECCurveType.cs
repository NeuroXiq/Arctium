namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    ///<summary>Type of curve used in key exchange messages</summary>
    enum ECCurveType :byte
    {
        ///<summary>Deprecated</summary>
        ExplicitPrime= 1,
        ///<summary>Deprecated</summary>
        ExplicitChar2= 2,
        ///<summary>Indicates that curve will be taken from SEC 2 curves list</summary>
        NamedCurve = 3,
    }
}
