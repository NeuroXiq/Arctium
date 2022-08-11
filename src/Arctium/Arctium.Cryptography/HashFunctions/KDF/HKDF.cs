using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Cryptography.HashFunctions.KDF
{
    /// <summary>
    /// RFC 5869
    /// </summary>
    internal class HKDF
    {

        /// <summary>
        /// 
        /// </summary>
        /// <param name="salt">
        /// Optional salt value (a non-secret random value) if not provided,
        /// it is set to a string of HashLen zeros.</param>
        /// <param name="ikm">
        /// Input keying material
        /// </param>
        public void Extract(byte[] salt, byte[] ikm)
        {

        }

        public void Expand()
        {
        
        }
    }
}
