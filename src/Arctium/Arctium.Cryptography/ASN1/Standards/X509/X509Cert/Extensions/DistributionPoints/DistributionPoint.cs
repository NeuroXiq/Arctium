using Arctium.Cryptography.ASN1.Standards.X501.Types;

using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    public class DistributionPoint
    {
        // internal purpose constructor values for this extension.
        // This extension is internally more complicated because all of the values are OPTIONAL
        // and this class as a public interface representing this extension must have a valid inner state
        internal struct ConstructorValues
        {
            public bool IsDistributionPointPresent;
            public bool IsReasonsPresent;
            public bool IsCRLIssuerPresent;

            public DistributionPointNameType DPNType;
            public ReasonFlags Reasons;
            public object DistributionPointNameObject;
            public GeneralName[] GeneralNames;

            /// <summary>
            /// Creates Constructor values as if all OPTIONAL fields are ommitted.
            /// </summary>
            /// <returns></returns>
            public static ConstructorValues CreateEmpty()
            {
                // Just to explicitly create this empty object, 
                // to show how it should look on initial state

                ConstructorValues empty = new ConstructorValues();
                empty.IsDistributionPointPresent =
                    empty.IsReasonsPresent =
                    empty.IsCRLIssuerPresent = false;
                empty.DPNType = DistributionPointNameType.FullName; // must be assigned, but must be ignored
                empty.Reasons = ReasonFlags.AACompromise; // must be assigned, must be ignored 
                empty.DistributionPointNameObject = null;
                empty.GeneralNames = null;

                return empty;
            }
        }

        private ConstructorValues innerValues;

        /// <summary>
        /// Indicates type of the DistributionPointName field. If <see cref="IsDistributionPointPreset"/> is false, 
        /// this field MUST be ignored in extenions processing.
        /// </summary>
        public DistributionPointNameType PointNameType { get { return innerValues.DPNType; } }

        /// <summary>
        /// Flags enum represents reasons field/>
        /// </summary>
        public ReasonFlags Reasons { get { return innerValues.Reasons; } }

        /// <summary>
        /// Indicates if <see cref="GetDistributionPoint{T}"/> value exists. Distribution point is OPTIONAL
        /// </summary>
        public bool IsDistributionPointPreset { get { return innerValues.IsDistributionPointPresent; } }
        /// <summary>
        /// Indicates if <see cref="ReasonFlags"/> exists. If this fields is set to false, <see cref="ReasonFlags"/> can be ignored.
        /// </summary>
        public bool IsReasonsPreset { get { return innerValues.IsReasonsPresent; } }

        public bool IsCRLIssuerPresent { get { return innerValues.IsCRLIssuerPresent; } }

        internal DistributionPoint(ConstructorValues constructorValues)
        {
            if (constructorValues.DistributionPointNameObject != null)
                ThrowIfInvalidDistrPointGeneric(constructorValues.DistributionPointNameObject.GetType());

            innerValues = constructorValues;
        }

        /// <summary>
        /// Get typed distribution point name of the current DistributionPointsExtenions object. <br/>
        /// Type of inner extension is determined by <see cref="PointNameType"/> field.
        /// This value can be null, if <see cref="IsDistributionPointPreset"/> is set to false (method call throws exception)
        /// </summary>
        /// <typeparam name="T">Is one of the following: <br/>
        /// <seealso cref="GeneralName[]"/><br/>
        /// <seealso cref="RelativeDistinguishedName"/><typeparamref name="T"/>
        /// <returns>Converted DistributionPointName object to proper value </returns>
        /// 
        public T GetDistributionPoint<T>()
        {
            ThrowIfInvalidDistrPointGeneric(typeof(T));
            if (IsDistributionPointPreset)
                throw new NullReferenceException("Cannot get DistributionPoint of this extension because is not present (OPTIONAL value is null)");

            return (T)innerValues.DistributionPointNameObject;
        }

        private void ThrowIfInvalidDistrPointGeneric(Type castType)
        {
            if ((castType != typeof(GeneralName[])) && 
                (castType != typeof(RelativeDistinguishedName)))
            {
                throw new InvalidCastException("Current casting is not valid for the DistributionPointName object. ");
            }
        }
    }
}
