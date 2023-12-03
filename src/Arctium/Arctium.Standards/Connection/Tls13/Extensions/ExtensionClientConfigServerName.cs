using Arctium.Shared.Other;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Arctium.Standards.Connection.Tls13.Extensions
{
    /// <summary>
    /// Configuration for Server name extension RFC 6066 on client side
    /// </summary>
    public class ExtensionClientConfigServerName
    {
        internal byte[] HostName { get; private set; }

        /// <summary>
        /// Initializes new instance with server name as byte array (ascii encoded byte array of host name)
        /// </summary>
        /// <param name="hostName">ASCII encoded bytes of host name string</param>
        public ExtensionClientConfigServerName(byte[] hostName)
        {
            Constructor(hostName);
        }

        /// <summary>
        /// Intializes new instance with host name as a string. 
        /// String is converter into byte array using ASCII encoding.
        /// </summary>
        /// <param name="hostName">Host name where TLS client is willing to connect</param>
        public ExtensionClientConfigServerName(string hostName)
        {
            Validation.NotEmpty(hostName, nameof(hostName));
            Constructor(Encoding.ASCII.GetBytes(hostName));
        }

        private void Constructor(byte[] hostName)
        {
            Validation.NotEmpty(hostName, nameof(hostName), "host name cannot be empty");
            Validation.Argument(hostName.All(b => b == 0), nameof(hostName), "all bytes are zero");
            HostName = hostName;
        }

        ///// <summary>
        ///// Adds host name as ASCII encoded bytes.
        ///// </summary>
        ///// <param name="hostName">Host name as ascii encoded byte array</param>
        //public void AddHostName(byte[] hostName)
        //{
        //    Validation.NotEmpty(hostName, nameof(hostName));
        //    Validation.Argument(hostName.All(b => b == 0), nameof(hostName), "all bytes of host name are zero-bytes");

        //    HostNames.Add(hostName);
        //}

        ///// <summary>
        ///// Adds host name as string. String is converted to bytes by ASCII encoding.
        ///// Name must not be null or empty
        ///// </summary>
        ///// <param name="hostName"></param>
        //public void AddHostName(string hostName)
        //{
        //    Validation.Argument(string.IsNullOrWhiteSpace(hostName), nameof(hostName), "host name is null or white space");
        //    var bytes = Encoding.ASCII.GetBytes(hostName);
        //    AddHostName(bytes);
        //}
    }
}
