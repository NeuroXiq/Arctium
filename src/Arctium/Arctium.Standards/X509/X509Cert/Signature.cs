//using Arctium.Standards.ASN1.Shared.Exceptions;
//using Arctium.Standards.X509.X509Cert.Algorithms;
//using System;

//namespace Arctium.Standards.X509.X509Cert
//{
//    public class Signature
//    {
//        public SignatureAlgorithm AlgorithmType { get; private set; }

//        object genericParmsValue;
//        object genericValue;

//        /// <summary>
//        /// Returns typed representation of the parameters for specific 
//        /// signature algorithm. Type of the returned value depends 
//        /// on <see cref="AlgorithmType"/>
//        /// </summary>
//        /// <typeparam name="T">Parameters to convert</typeparam>
//        /// <returns></returns>
//        /// <exception cref="ASN1InvalidCastException">
//        /// Throws when cast is invalid or parameters 
//        /// for specific algorithm do not extists (null)
//        /// </exception>
//        public T GetParms<T>()
//        {
//            if (genericParmsValue == null)
//            {
//                throw new ASN1CastException(null, typeof(T),
//                    "Current value of the parameters are null and cannot be casted to typed object. " +
//                    "AlgorithmType indicates, that parameters do not exists for this type of signing");
//            }

//            return (T)genericParmsValue;
//        }


//        public T GetValue<T>()
//        {
//            return default(T);
//            //return (byte[])
//        }

//        internal Signature(SignatureAlgorithm algorithm, object parms, object signatureValue)
//        {
//            AlgorithmType = algorithm;
//            genericParmsValue = parms;
//            genericValue = signatureValue;
//        }
//    }
//}
