namespace Arctium.Cryptography.HashFunctions.CRC
{
    /// <summary>
    /// https://reveng.sourceforge.io/crc-catalogue/1-15.htm
    /// </summary>
    public static class PredefinedCRC
    {
        /// <summary>
        /// width=8 poly=0xd5 init=0x00 refin=false refout=false xorout=0x00 check=0xbc residue=0x00 name="CRC-8/DVB-S2"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_DVB_S2() => new CRC8(0xD5, 0, false, false, 0);

        public static CRC8 CRC8_AUTOSAR() => new CRC8(0x2f, 0xff, false, false, 0xff);
        
        public static CRC8 CRC8_Bluetooth() => new CRC8(0xA7, 0, true, true, 0);

        /// <summary>
        /// width=8 poly=0x9b init=0xff refin=false refout=false xorout=0x00 check=0xda residue=0x00 name="CRC-8/CDMA2000"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_CDMA2000() => new CRC8("CRC-8/CDMA2000", 0x9B, 0xFF, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x39 init=0x00 refin=true refout=true xorout=0x00 check=0x15 residue=0x00 name="CRC-8/DARC"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_DARD() => new CRC8("CRC-8/DARC", 0x39, 0x00, 0x00, true, true);

        /// <summary>
        /// width=8 poly=0x1d init=0x00 refin=false refout=false xorout=0x00 check=0x37 residue=0x00 name="CRC-8/GSM-A"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_GSMA() => new CRC8("CRC-8/GSM-A", 0x1d, 0x00, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x49 init=0x00 refin=false refout=false xorout=0xff check=0x94 residue=0x53 name="CRC-8/GSM-B"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_GSMB() => new CRC8("CRC-8/GSM-B", 0x49, 0x00, 0xFF, false, false);

        /// <summary>
        ///width=8 poly=0x1d init=0xff refin=false refout=false xorout=0x00 check=0xb4 residue=0x00 name="CRC-8/HITAG"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_HITAG() => new CRC8("CRC-8/HITAG", 0x1d, 0xFF, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x07 init=0x00 refin=false refout=false xorout=0x55 check=0xa1 residue=0xac name="CRC-8/I-432-1"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_I_432_1() => new CRC8("CRC-8/I-432-1", 0x07, 0x00, 0x55, false, false);

        /// <summary>
        /// width=8 poly=0x1d init=0xfd refin=false refout=false xorout=0x00 check=0x7e residue=0x00 name="CRC-8/I-CODE"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_I_CODE() => new CRC8("CRC-8/I-CODE", 0x1d, 0xfd, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x9b init=0x00 refin=false refout=false xorout=0x00 check=0xea residue=0x00 name="CRC-8/LTE"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_I_LTE() => new CRC8("CRC-8/LTE", 0x9b, 0x00, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x31 init=0x00 refin=true refout=true xorout=0x00 check=0xa1 residue=0x00 name="CRC-8/MAXIM-DOW"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_MAXIM_DOW() => new CRC8("CRC-8/MAXIM-DOW", 0x31, 0, 0, true, true);

        /// <summary>
        /// idth=8 poly=0x1d init=0xc7 refin=false refout=false xorout=0x00 check=0x99 residue=0x00 name="CRC-8/MIFARE-MAD"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_MIFARE_MAD() => new CRC8("CRC-8/MIFARE-MAD", 0x1d, 0xc7, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x31 init=0xff refin=false refout=false xorout=0x00 check=0xf7 residue=0x00 name="CRC-8/NRSC-5"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_NRSC_5() => new CRC8("CRC-8/NRSC-5", 0x31, 0xff, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x2f init=0x00 refin=false refout=false xorout=0x00 check=0x3e residue=0x00 name="CRC-8/OPENSAFETY"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_OPENSAFETY() => new CRC8("CRC-8/OPENSAFETY", 0x2f, 0x00, 0x00, false, false);

        /// <summary>
        /// width=8 poly=0x07 init=0xff refin=true refout=true xorout=0x00 check=0xd0 residue=0x00 name="CRC-8/ROHC"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8_ROHC() => new CRC8("CRC-8/OPENSAFETY", 0x07, 0xff, 0x00, true, true);

        /// <summary>
        /// width=8 poly=0x1d init=0xff refin=false refout=false xorout=0xff check=0x4b residue=0xc4 name="CRC-8/SAE-J1850"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8SAE_J1850() => new CRC8("CRC-8/SAE-J1850", 0x1d, 0xff, 0xff, false, false);

        /// <summary>
        /// width=8 poly=0x07 init=0x00 refin=false refout=false xorout=0x00 check=0xf4 residue=0x00 name="CRC-8/SMBUS"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8SAE_SMBUS() => new CRC8("CRC-8/SMBUS", 0x07, 0x00, 0xff, false, false);

        /// <summary>
        /// width=8 poly=0x1d init=0xff refin=true refout=true xorout=0x00 check=0x97 residue=0x00 name="CRC-8/TECH-3250"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8SAE_TECH_3250() => new CRC8("CRC-8/TECH-3250", 0x1d, 0xff, 0x00, true, true);

        /// <summary>
        /// width=8 poly=0x9b init=0x00 refin=true refout=true xorout=0x00 check=0x25 residue=0x00 name="CRC-8/WCDMA"
        /// </summary>
        /// <returns></returns>
        public static CRC8 CRC8SAE_WCDMA() => new CRC8("CRC-8/WCDMA", 0x9b, 0x00, 0x00, true, true);


        //
        // CRC-32
        //

        /// <summary>
        /// width=32 poly=0x814141ab init=0x00000000 refin=false refout=false xorout=0x00000000 check=0x3010bf7f residue=0x00000000 name="CRC-32/AIXM"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_AIXM() => new CRC32("CRC-32/AIXM", 0x814141ab, 0x00, 0x00, false, false);

        /// <summary>
        /// width=32 poly=0xf4acfb13 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0x1697d06a residue=0x904cddbf name="CRC-32/AUTOSAR"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_AUTOSAR() => new CRC32("CRC-32/AUTOSAR", 0xf4acfb13, 0xffffffff, 0xffffffff, true, true);

        /// <summary>
        /// width=32 poly=0xa833982b init=0xffffffff refin=true refout=true xorout=0xffffffff check=0x87315576 residue=0x45270551 name="CRC-32/BASE91-D"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_BASE91_D() => new CRC32("CRC-32/BASE91-D", 0xa833982b, 0xffffffff, 0xffffffff, true, true);

        /// <summary>
        /// width=32 poly=0x04c11db7 init=0xffffffff refin=false refout=false xorout=0xffffffff check=0xfc891918 residue=0xc704dd7b name="CRC-32/BZIP2"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_BZIP2() => new CRC32("CRC-32/BZIP2", 0x04c11db7, 0xffffffff, 0xffffffff, false, false);

        /// <summary>
        /// width=32 poly=0x8001801b init=0x00000000 refin=true refout=true xorout=0x00000000 check=0x6ec2edc4 residue=0x00000000 name="CRC-32/CD-ROM-EDC"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_CD_ROM_EDC() => new CRC32("CRC-32/CD-ROM-EDC", 0x8001801b, 0, 0, true, true);

        /// <summary>
        /// width=32 poly=0x04c11db7 init=0x00000000 refin=false refout=false xorout=0xffffffff check=0x765e7680 residue=0xc704dd7b name="CRC-32/CKSUM"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_CKSUM() => new CRC32("CRC-32/CKSUM", 0x04c11db7, 0, 0, false, false);

        /// <summary>
        /// width=32 poly=0x1edc6f41 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xe3069283 residue=0xb798b438 name="CRC-32/ISCSI"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_ISCSI() => new CRC32("CRC-32/ISCSI", 0x1edc6f41, 0xffffffff, 0xffffffff, true, true);

        /// <summary>
        /// width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926 residue=0xdebb20e3 name="CRC-32/ISO-HDLC"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_ISO_HDLC() => new CRC32("CRC-32/ISO-HDLC", 0x04c11db7, 0xffffffff, 0xffffffff, true, true);

        /// <summary>
        /// width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0x00000000 check=0x340bc6d9 residue=0x00000000 name="CRC-32/JAMCRC"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_JAMCRC() => new CRC32("CRC-32/JAMCRC", 0x04c11db7, 0xffffffff, 0xffffffff, true, true);

        /// <summary>
        /// width=32 poly=0x741b8cd7 init=0xffffffff refin=true refout=true xorout=0x00000000 check=0xd2c22f51 residue=0x00000000 name="CRC-32/MEF"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_MEF() => new CRC32("CRC-32/MEF", 0x741b8cd7, 0xffffffff, 0xffffffff, true, true);

        /// <summary>
        /// width=32 poly=0x04c11db7 init=0xffffffff refin=false refout=false xorout=0x00000000 check=0x0376e6e7 residue=0x00000000 name="CRC-32/MPEG-2"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_MPEG_2() => new CRC32("CRC-32/MPEG_2", 0x04c11db7, 0xffffffff, 0, false, false);

        /// <summary>
        /// width=32 poly=0x000000af init=0x00000000 refin=false refout=false xorout=0x00000000 check=0xbd0be338 residue=0x00000000 name="CRC-32/XFER"
        /// </summary>
        /// <returns></returns>
        public static CRC32 CRC32_XFER() => new CRC32("CRC-32/XFER", 0x000000af, 0, 0, false, false);

        //
        // CRC-64
        //

        /// <summary>
        /// width=64 poly=0x000000000000001b init=0xffffffffffffffff refin=true refout=true xorout=0xffffffffffffffff check=0xb90956c775a41001 residue=0x5300000000000000 name="CRC-64/GO-ISO"
        /// </summary>
        /// <returns></returns>
        public static CRC64 CRC64_GO_ISO() => new CRC64("CRC-64/GO-ISO", 0x000000000000001b, 0xffffffffffffffff, 0xffffffffffffffff, true, true);

        /// <summary>
        /// width=64 poly=0x259c84cba6426349 init=0xffffffffffffffff refin=true refout=true xorout=0x0000000000000000 check=0x75d4b74f024eceea residue=0x0000000000000000 name="CRC-64/MS"
        /// </summary>
        /// <returns></returns>
        public static CRC64 CRC64_MS() => new CRC64("CRC-64/MS", 0x259c84cba6426349, 0xffffffffffffffff, 0x0000000000000000, true, true);

        /// <summary>
        /// width=64 poly=0x42f0e1eba9ea3693 init=0xffffffffffffffff refin=false refout=false xorout=0xffffffffffffffff check=0x62ec59e3f1a4f00a residue=0xfcacbebd5931a992 name="CRC-64/WE"
        /// </summary>
        /// <returns></returns>
        public static CRC64 CRC64_WE() => new CRC64("CRC-64/WE", 0x42f0e1eba9ea3693, 0xffffffffffffffff, 0xffffffffffffffff, false, false);

        /// <summary>
        /// width=64 poly=0x42f0e1eba9ea3693 init=0xffffffffffffffff refin=true refout=true xorout=0xffffffffffffffff check=0x995dc9bbdf1939fa residue=0x49958c9abd7d353f name="CRC-64/XZ"
        /// </summary>
        /// <returns></returns>
        public static CRC64 CRC64_XZ() => new CRC64("CRC-64/XZ", 0x42f0e1eba9ea3693, 0xffffffffffffffff, 0xffffffffffffffff, true, true);

        /// <summary>
        /// width=64 poly=0x42f0e1eba9ea3693 init=0x0000000000000000 refin=false refout=false xorout=0x0000000000000000 check=0x6c40df5f0b497347 residue=0x0000000000000000 name="CRC-64/ECMA-182"
        /// </summary>
        /// <returns></returns>
        public static CRC64 CRC64_ECMA182() => new CRC64("CRC-64/ECMA-182", 0x42f0e1eba9ea3693, 0, 0, false, false);
    }
}
