//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//


using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using System;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static byte[] encodedData = new byte[]
        {
            0x30, 0x13, 0x02, 0x01, 0x05, 0x16, 0x0e, 0x41, 0x6e,
            0x79, 0x62, 0x6f, 0x64, 0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f,
        };

        static void Main(string[] args)
        {
            DerDeserializer der = new DerDeserializer();
            X690DecodedNode metadataDecodedNode = der.Deserialize(encodedData);

            // always perform this step (get first inner result)
            // let me explaint whats going on here (why '[0]'): 
            // Current implementation of decoder returns 'non-existring', special
            // constructed type which holds decoded bytes. To get 
            // decoded structure, we need to take first constructed type of this 
            // 'special-root-node' to retrieve decoded structure. 
            // This step is ALWAYS performed.
            X690DecodedNode decodedBytesRootNode = metadataDecodedNode[0];

            // lets look around what we get after decoding.
            // first take a look at decoded node:

            var node = decodedBytesRootNode;

            // where this node 'is' in encoded byte array ?
            Console.WriteLine("Content-length: " + node.ContentLength);
            Console.WriteLine("Constructed count: " + node.ConstructedCount);
            Console.WriteLine("Content offest: " + node.ContentOffset);
            

            /* OUTPUT: 
             * Content-length: 19
             * Constructed count: 2
             * Content offest: 2
             */

            // constructted count indicated how many values are in 
            // this node, if this node is a constructed

            // values of 'BufferFrame'

            // where this frame is in encoded bytes ? 
            Console.WriteLine("Frame offset: " + node.FrameOffset);

            Console.WriteLine("Informations about encoded type in this frame");  
            Console.WriteLine("Length is definit form ? (or undefinite): " + node.Frame.ContentLength.IsDefinite);
            Console.WriteLine("Frame length: " + node.Frame.FrameLength);
            Console.WriteLine("Primitive/Constructed enum: " + node.Frame.PC.ToString());

            Console.WriteLine("What type (tag) this frame holds ? ");
            Console.WriteLine("Class number: " + node.Frame.ClassNumber);
            Console.WriteLine("Tag number: " + node.Frame.TagNumber);
            Console.WriteLine("Tag (this 2 values above as tag): " + node.Frame.Tag.ToString());

            /* [Output]
             * 
             * Frame offset: 0
             * Informations about encoded type in this frame
             * Length is definit form ? (or undefinite): True
             * Frame length: 2
             * Primitive/Constructed enum: Constructed
             * What type (tag) this frame holds ?
             * Class number: 0
             * Tag number: 16
             * Tag (this 2 values above as tag): Universal:Sequence (0, 16)
             */

            // now we known, that this frame is a SEQUENCE (see last output value => Tag)
            // everything is fine, 'FooQuestion' structure consists of 
            // 'SEQUENCE', and this sequence contains 2 values.
            // And this means, that this node points to first 
            // 'SEQUENCE' of 'FooQuestion'

            // how to get some inner types ? 
            // get constructued content from node field: 

            var content = node.ConstructedContent;
            // content holds X690DecodedNode as a List<X690DecodedNode> 
            // object

            // we expect to have 2 values of constructed type (trankingNumber and question)
            Console.WriteLine("Content count: " + content.Count);

            // [Output]
            // Content count: 2

            //content shall contain 2 values : trackingNumber + question

            var trackingNumberNode = content[0];
            var question = content[1];

            // show types of this 2 values:

            Console.WriteLine("First tag: " + trackingNumberNode.Frame.Tag.ToString());
            Console.WriteLine("Second tag: " + question.Frame.Tag.ToString());

            /* [Output]
             * First tag: Universal:Integer (0, 2)
             * Second tag: Universal:IA5String (0, 22)
             */

            // as we can see, this tags match inner values
            // of a FooQuestion sequence.

            // next we can decode this values
            // node decodint of concrete type (e.g. ASN1 INTEGER) require
            // decoders. DER decoders for asn1 types are located in convenient 
            // class 'DerDecoders'

            Integer trackingNumber = DerDecoders.DecodeWithoutTag<Integer>(trackingNumberNode);
            IA5String questionString = DerDecoders.DecodeWithoutTag<IA5String>(question);

            // types above are 'ASN.1' types
            // but they contains overloaded operators and 
            // can be mapped directly to CRL types (is possible)

            // this works directly by assignment:

            uint trackNum = trackingNumber;
            string questionStr = questionString;

            Console.WriteLine("trackNum: " + trackNum);
            Console.WriteLine("questionStr: " + questionStr);

            /*
             * trackNum: 5
             * questionStr: Anybody there?
             */


            /*
             * This was a basic ASN.1 DER decoder. 
             * Other documetation can be found in 
             * assembly as a 
             * ///<summary>...</summary>
             */


        }
    }
}
