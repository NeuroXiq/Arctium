```
byte[] input = new byte[1234];
Skein_512 skein512 = new Skein_512();
Skein_256 skein256 = new Skein_256();
Skein_1024 skein1024 = new Skein_1024();

skein512.HashBytes(input, 0, 1000);
skein512.HashBytes(input, 1000, 234);

byte[] hash = skein512.HashFinal();

Console.WriteLine("Skein-512: ");
MemDump.HexDump(hash);

Skein_VAR skein_1024_output_128 = new Skein_VAR(Skein.InternalStateSize.Bits_1024, 128);
Skein_VAR skein_512_output_384 = new Skein_VAR(Skein.InternalStateSize.Bits_512, 384);
Skein_VAR skein_256_output_128 = new Skein_VAR(Skein.InternalStateSize.Bits_256, 128);

skein_1024_output_128.HashBytes(input);
skein_512_output_384.HashBytes(input);
skein_256_output_128.HashBytes(input);

byte[] s1 = skein_1024_output_128.HashFinal();
byte[] s2 = skein_512_output_384.HashFinal();
byte[] s3 = skein_256_output_128.HashFinal();

Console.WriteLine("skein_1024_output_128");
MemDump.HexDump(s1);
Console.WriteLine("skein_512_output_384");
MemDump.HexDump(s2);
Console.WriteLine("skein_256_output_128");
MemDump.HexDump(s3);


/* [Output]: 
 * 
 * Skein-512:
 * 6F522586 A1660A7F F5B196AF F2B9B67E
 * 758651F8 F3A4019B 12D4269B 33B20CC7
 * 78F6B751 76DB26EF 255DED70 F2449AFE
 * 03A744B7 623B1A52 C8005D3C AE509E5C
 * 
 * skein_1024_output_128
 * 29EC8F68 002D9C0B 05CF2E91 6E879DD5
 * 
 * skein_512_output_384
 * D21874CE 7FE36806 C956062D E1ECA622
 * FF894D01 83CFCA55 CDEF5FED 10515F81
 * A5385ED7 31B3B673 D0D2DFDC 020D8155
 * 
 * skein_256_output_128
 * EF96AB10 1FDED856 31E92815 DFA041AE
 * 
 */
```