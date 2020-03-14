using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;

namespace Arctium.Encoding.IDL.ASN1.Mapper.Attributes
{
    [System.AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    sealed class SequenceAttribute : Asn1TypeAttribute
    {
        public string[] OrderedTypeList { get; set; }
        
        public SequenceAttribute(object parameters) : base(BuildInTag.Sequence, parameters) 
        {

        }
    }
}
