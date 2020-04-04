$c = ("BitStringType",
"BooleanType",
"CharacterStringType",
"ChoiceType",
"DateType",
"DateTimeType",
"DurationType",
"EmbeddedPDVType",
"EnumeratedType",
"ExternalType",
"InstanceOfType",
"IntegerType",
"IRIType",
"NullType",
"ObjectClassFieldType",
"ObjectIdentifierType",
"OctetStringType",
"RealType",
"RelativeIRIType",
"RelativeOIDType",
"SequenceType",
"SequenceOfType",
"SetType",
"SetOfType",
"PrefixedType",
"TimeType",
"TimeOfDayType")

# $c = "test";

foreach($a in $c)
{
	$fileName = ("{0}.cs" -f $a);
	new-item $fileName -type file;
	
	
	$scaff = "using System;`r`n`r`n";
	$scaff += "namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes`r`n{`r`n";
	$scaff += "{1}public class {0}<T>: TaggedType<T>" -f $a,"`t";
	# $scaff += "`r`n{`r`n`r`n}`r`n";
	$scaff += "`r`n{0}{{`r`n" -f "`t";
	$scaff += '{1}public {0}(): base(null) {{ throw new Exception("Not implemented"); }}' -f $a,"`t`t";
	$scaff += "`r`n{0}}}" -f "`t"
	$scaff += "`r`n}";
	echo $scaff | out-file -filepath $fileName;
	
	
	
}

# remove-item test.cs

