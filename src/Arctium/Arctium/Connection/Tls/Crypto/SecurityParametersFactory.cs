using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Crypto
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

            secParams.ServerRandom = null;
            secParams.MasterSecret = null;
            secParams.KeySize = 0;
            secParams.KeyMaterialSize = 0;
            secParams.HashSize = 0;

            return secParams;
        }
    }
}
