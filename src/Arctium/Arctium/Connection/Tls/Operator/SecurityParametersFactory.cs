using Arctium.Connection.Tls.Protocol;

namespace Arctium.Connection.Tls.Operator
{
    class SecurityParametersFactory
    {
        public SecurityParametersFactory() { }


        ///<summary>
        /// Creates <see cref="SecurityParameters"/> instance with inital
        /// state described in the RFC 4346 (TLS/1.1)
        /// </summary>
        /// ///<param name="entityType">Entity type indicates if current host is server or client</param>
        public SecurityParameters BuildInitialState(ConnectionEnd entityType)
        {
            SecurityParameters secParams = new SecurityParameters();

            secParams.CompressionAlgorithm = CompressionMethod.NULL;
            secParams.MACAlgorithm = MACAlgorithm.NULL;
            secParams.BulkCipherAlgorithm = BulkCipherAlgorithm.NULL;
            secParams.Entity = entityType;

            return secParams;
        }
    }
}
