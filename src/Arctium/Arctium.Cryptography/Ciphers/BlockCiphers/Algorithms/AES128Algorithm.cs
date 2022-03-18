﻿using Arctium.Shared.Helpers.Buffers;
using System.Runtime.CompilerServices;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms
{
    public unsafe class AESOptimizedAlgorithm
    {
        static byte* sbox = AESAlgorithm.SboxPtr;
        static uint* T1, T2, T3, T4;
        static uint* InvT1, InvT2, InvT3, InvT4;

        static byte* InverseSbox;

        static AESOptimizedAlgorithm()
        {
            InverseSbox = AESAlgorithm.InverseSboxPtr;
            T1 = AESAlgorithm.T1Ptr;
            T2 = AESAlgorithm.T2Ptr;
            T3 = AESAlgorithm.T3Ptr;
            T4 = AESAlgorithm.T4Ptr;

            InvT1 = AESAlgorithm.InvT1Ptr;
            InvT2 = AESAlgorithm.InvT2Ptr;
            InvT3 = AESAlgorithm.InvT3Ptr;
            InvT4 = AESAlgorithm.InvT4Ptr;
        }

        public static void DecryptBlock192(uint* scheduledKey, byte* input, byte* output)
        {
            byte* state = stackalloc byte[16];
            uint key, res;
            uint* expandedKey = scheduledKey;
            byte b1, b2, b3, b4;
            state[0] = input[0];
            state[4] = input[1];
            state[8] = input[2];
            state[12] = input[3];
            state[1] = input[4];
            state[5] = input[5];
            state[9] = input[6];
            state[13] = input[7];
            state[2] = input[8];
            state[6] = input[9];
            state[10] = input[10];
            state[14] = input[11];
            state[3] = input[12];
            state[7] = input[13];
            state[11] = input[14];
            state[15] = input[15];
            key = expandedKey[48];
            state[0] ^= (byte)(key >> 24);
            state[4] ^= (byte)(key >> 16);
            state[8] ^= (byte)(key >> 08);
            state[12] ^= (byte)(key >> 00);
            key = expandedKey[49];
            state[1] ^= (byte)(key >> 24);
            state[5] ^= (byte)(key >> 16);
            state[9] ^= (byte)(key >> 08);
            state[13] ^= (byte)(key >> 00);
            key = expandedKey[50];
            state[2] ^= (byte)(key >> 24);
            state[6] ^= (byte)(key >> 16);
            state[10] ^= (byte)(key >> 08);
            state[14] ^= (byte)(key >> 00);
            key = expandedKey[51];
            state[3] ^= (byte)(key >> 24);
            state[7] ^= (byte)(key >> 16);
            state[11] ^= (byte)(key >> 08);
            state[15] ^= (byte)(key >> 00);
            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[44];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[45];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[46];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[47];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[40];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[41];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[42];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[43];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[36];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[37];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[38];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[39];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[32];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[33];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[34];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[35];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[28];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[29];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[30];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[31];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[24];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[25];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[26];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[27];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[20];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[21];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[22];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[23];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[16];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[17];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[18];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[19];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[12];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[13];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[14];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[15];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[8];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[9];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[10];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[11];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[4];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[5];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[6];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[7];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[0];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[0] = b1;
            output[1] = b2;
            output[2] = b3;
            output[3] = b4;
            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[1];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[4] = b1;
            output[5] = b2;
            output[6] = b3;
            output[7] = b4;
            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[2];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[8] = b1;
            output[9] = b2;
            output[10] = b3;
            output[11] = b4;
            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[3];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[12] = b1;
            output[13] = b2;
            output[14] = b3;
            output[15] = b4;
        }


        public static void EncryptBlock192(uint* scheduledKey, byte* input, byte* output)
        {
            byte* state = stackalloc byte[16];
            byte b1, b2, b3, b4;
            uint k;
            uint* roundKey = scheduledKey;
            uint xored = 0;
            state[0] = input[0];
            state[1] = input[4];
            state[2] = input[8];
            state[3] = input[12];
            state[4] = input[1];
            state[5] = input[5];
            state[6] = input[9];
            state[7] = input[13];
            state[8] = input[2];
            state[9] = input[6];
            state[10] = input[10];
            state[11] = input[14];
            state[12] = input[3];
            state[13] = input[7];
            state[14] = input[11];
            state[15] = input[15];
            // Add Round Key (Round 0)
            k = roundKey[0];
            state[0] ^= (byte)((k >> 24) & 0xFF);
            state[4] ^= (byte)((k >> 16) & 0xFF);
            state[8] ^= (byte)((k >> 08) & 0xFF);
            state[12] ^= (byte)((k >> 00) & 0xFF);
            k = roundKey[1];
            state[1] ^= (byte)((k >> 24) & 0xFF);
            state[5] ^= (byte)((k >> 16) & 0xFF);
            state[9] ^= (byte)((k >> 08) & 0xFF);
            state[13] ^= (byte)((k >> 00) & 0xFF);
            k = roundKey[2];
            state[2] ^= (byte)((k >> 24) & 0xFF);
            state[6] ^= (byte)((k >> 16) & 0xFF);
            state[10] ^= (byte)((k >> 08) & 0xFF);
            state[14] ^= (byte)((k >> 00) & 0xFF);
            k = roundKey[3];
            state[3] ^= (byte)((k >> 24) & 0xFF);
            state[7] ^= (byte)((k >> 16) & 0xFF);
            state[11] ^= (byte)((k >> 08) & 0xFF);
            state[15] ^= (byte)((k >> 00) & 0xFF);

            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[4];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[5];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[6];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[7];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[8];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[9];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[10];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[11];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[12];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[13];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[14];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[15];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[16];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[17];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[18];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[19];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[20];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[21];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[22];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[23];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[24];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[25];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[26];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[27];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[28];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[29];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[30];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[31];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[32];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[33];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[34];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[35];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[36];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[37];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[38];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[39];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[40];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[41];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[42];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[43];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[44];
            xored ^= k;

            state[0] = (byte)(xored >> 24);
            state[7] = (byte)(xored >> 16);
            state[10] = (byte)(xored >> 08);
            state[13] = (byte)(xored >> 00);

            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[45];
            xored ^= k;

            state[1] = (byte)(xored >> 24);
            state[4] = (byte)(xored >> 16);
            state[11] = (byte)(xored >> 08);
            state[14] = (byte)(xored >> 00);

            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[46];
            xored ^= k;

            state[2] = (byte)(xored >> 24);
            state[5] = (byte)(xored >> 16);
            state[8] = (byte)(xored >> 08);
            state[15] = (byte)(xored >> 00);

            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];

            xored = T1[b1] ^ T2[b2] ^ T3[b3] ^ T4[b4];


            k = roundKey[47];
            xored ^= k;

            state[3] = (byte)(xored >> 24);
            state[6] = (byte)(xored >> 16);
            state[9] = (byte)(xored >> 08);
            state[12] = (byte)(xored >> 00);
            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];
            b1 = sbox[b1];
            b2 = sbox[b2];
            b3 = sbox[b3];
            b4 = sbox[b4];
            k = roundKey[48];
            state[0] = (byte)(b1 ^ (k >> 24));
            state[4] = (byte)(b2 ^ (k >> 16));
            state[8] = (byte)(b3 ^ (k >> 08));
            state[12] = (byte)(b4 ^ (k >> 00));
            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];
            b1 = sbox[b1];
            b2 = sbox[b2];
            b3 = sbox[b3];
            b4 = sbox[b4];
            k = roundKey[49];
            state[1] = (byte)(b1 ^ (k >> 24));
            state[5] = (byte)(b2 ^ (k >> 16));
            state[9] = (byte)(b3 ^ (k >> 08));
            state[13] = (byte)(b4 ^ (k >> 00));
            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];
            b1 = sbox[b1];
            b2 = sbox[b2];
            b3 = sbox[b3];
            b4 = sbox[b4];
            k = roundKey[50];
            state[2] = (byte)(b1 ^ (k >> 24));
            state[6] = (byte)(b2 ^ (k >> 16));
            state[10] = (byte)(b3 ^ (k >> 08));
            state[14] = (byte)(b4 ^ (k >> 00));
            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];
            b1 = sbox[b1];
            b2 = sbox[b2];
            b3 = sbox[b3];
            b4 = sbox[b4];
            k = roundKey[51];
            state[3] = (byte)(b1 ^ (k >> 24));
            state[7] = (byte)(b2 ^ (k >> 16));
            state[11] = (byte)(b3 ^ (k >> 08));
            state[15] = (byte)(b4 ^ (k >> 00));
            output[0] = state[0];
            output[1] = state[4];
            output[2] = state[8];
            output[3] = state[12];
            output[4] = state[1];
            output[5] = state[5];
            output[6] = state[9];
            output[7] = state[13];
            output[8] = state[2];
            output[9] = state[6];
            output[10] = state[10];
            output[11] = state[14];
            output[12] = state[3];
            output[13] = state[7];
            output[14] = state[11];
            output[15] = state[15];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static void DecryptBlock(uint* k, byte* input, byte* output)
        {
            byte* state = stackalloc byte[16];
            byte b1, b2, b3, b4;
            uint key, res;
            uint* expandedKey = k;

            // ROUND 10

            state[0] = input[0];
            state[4] = input[1];
            state[8] = input[2];
            state[12] = input[3];
            state[1] = input[4];
            state[5] = input[5];
            state[9] = input[6];
            state[13] = input[7];
            state[2] = input[8];
            state[6] = input[9];
            state[10] = input[10];
            state[14] = input[11];
            state[3] = input[12];
            state[7] = input[13];
            state[11] = input[14];
            state[15] = input[15];

            // ADD ROUND KEY ROUND 10

            key = expandedKey[40];
            state[0] ^= (byte)(key >> 24);
            state[4] ^= (byte)(key >> 16);
            state[8] ^= (byte)(key >> 08);
            state[12] ^= (byte)(key >> 00);
            key = expandedKey[41];
            state[1] ^= (byte)(key >> 24);
            state[5] ^= (byte)(key >> 16);
            state[9] ^= (byte)(key >> 08);
            state[13] ^= (byte)(key >> 00);
            key = expandedKey[42];
            state[2] ^= (byte)(key >> 24);
            state[6] ^= (byte)(key >> 16);
            state[10] ^= (byte)(key >> 08);
            state[14] ^= (byte)(key >> 00);
            key = expandedKey[43];
            state[3] ^= (byte)(key >> 24);
            state[7] ^= (byte)(key >> 16);
            state[11] ^= (byte)(key >> 08);
            state[15] ^= (byte)(key >> 00);

            // ROUND 9

            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[36];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[37];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[38];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[39];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);

            // ROUND 8

            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[32];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[33];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[34];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[35];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);

            // ROUND 7

            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[28];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[29];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[30];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[31];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);

            // ROUND 6

            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[24];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[25];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[26];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[27];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);

            // ROUND 5

            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[20];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[21];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[22];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[23];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);

            // ROUND 4

            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[16];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[17];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[18];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[19];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);

            // ROUND 3

            b1 = state[0];
            b2 = state[5];
            b3 = state[10];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[12];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[6];
            b3 = state[11];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[13];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[7];
            b3 = state[8];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[14];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[4];
            b3 = state[9];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[15];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);

            // ROUND 2

            b1 = state[0];
            b2 = state[4];
            b3 = state[8];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[8];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[5];
            b3 = state[9];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[9];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[6];
            b3 = state[10];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[10];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[7];
            b3 = state[11];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[11];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);

            // ROUND 1

            b1 = state[0];
            b2 = state[7];
            b3 = state[10];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[4];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[0] = (byte)(res >> 24);
            state[7] = (byte)(res >> 16);
            state[10] = (byte)(res >> 08);
            state[13] = (byte)(res >> 00);
            b1 = state[1];
            b2 = state[4];
            b3 = state[11];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[5];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[1] = (byte)(res >> 24);
            state[4] = (byte)(res >> 16);
            state[11] = (byte)(res >> 08);
            state[14] = (byte)(res >> 00);
            b1 = state[2];
            b2 = state[5];
            b3 = state[8];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[6];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[2] = (byte)(res >> 24);
            state[5] = (byte)(res >> 16);
            state[8] = (byte)(res >> 08);
            state[15] = (byte)(res >> 00);
            b1 = state[3];
            b2 = state[6];
            b3 = state[9];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[7];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            res = InvT1[b1] ^ InvT2[b2] ^ InvT3[b3] ^ InvT4[b4];
            state[3] = (byte)(res >> 24);
            state[6] = (byte)(res >> 16);
            state[9] = (byte)(res >> 08);
            state[12] = (byte)(res >> 00);

            // FINAL

            b1 = state[0];
            b2 = state[6];
            b3 = state[8];
            b4 = state[14];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[0];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[0] = b1;
            output[1] = b2;
            output[2] = b3;
            output[3] = b4;
            b1 = state[1];
            b2 = state[7];
            b3 = state[9];
            b4 = state[15];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[1];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[4] = b1;
            output[5] = b2;
            output[6] = b3;
            output[7] = b4;
            b1 = state[2];
            b2 = state[4];
            b3 = state[10];
            b4 = state[12];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[2];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[8] = b1;
            output[9] = b2;
            output[10] = b3;
            output[11] = b4;
            b1 = state[3];
            b2 = state[5];
            b3 = state[11];
            b4 = state[13];
            b1 = InverseSbox[b1];
            b2 = InverseSbox[b2];
            b3 = InverseSbox[b3];
            b4 = InverseSbox[b4];
            key = expandedKey[3];
            b1 ^= (byte)(key >> 24);
            b2 ^= (byte)(key >> 16);
            b3 ^= (byte)(key >> 08);
            b4 ^= (byte)(key >> 00);
            output[12] = b1;
            output[13] = b2;
            output[14] = b3;
            output[15] = b4;
        }

        public static void EncryptBlock(/*AESAlgorithm.Context context*/ uint* roundKey, byte* input, byte* output)
        {
            byte* state = stackalloc byte[16];
            uint k;
            // uint[] roundKey = context.ExpandedKey;
            uint column;

            state[0] = input[0];
            state[1] = input[4];
            state[2] = input[8];
            state[3] = input[12];
            state[4] = input[1];
            state[5] = input[5];
            state[6] = input[9];
            state[7] = input[13];
            state[8] = input[2];
            state[9] = input[6];
            state[10] = input[10];
            state[11] = input[14];
            state[12] = input[3];
            state[13] = input[7];
            state[14] = input[11];
            state[15] = input[15];

            // Add Round Key (Round 0)

            k = roundKey[0];
            state[0] ^= (byte)((k >> 24) & 0xFF);
            state[4] ^= (byte)((k >> 16) & 0xFF);
            state[8] ^= (byte)((k >> 08) & 0xFF);
            state[12] ^= (byte)((k >> 00) & 0xFF);
            k = roundKey[1];
            state[1] ^= (byte)((k >> 24) & 0xFF);
            state[5] ^= (byte)((k >> 16) & 0xFF);
            state[9] ^= (byte)((k >> 08) & 0xFF);
            state[13] ^= (byte)((k >> 00) & 0xFF);
            k = roundKey[2];
            state[2] ^= (byte)((k >> 24) & 0xFF);
            state[6] ^= (byte)((k >> 16) & 0xFF);
            state[10] ^= (byte)((k >> 08) & 0xFF);
            state[14] ^= (byte)((k >> 00) & 0xFF);
            k = roundKey[3];
            state[3] ^= (byte)((k >> 24) & 0xFF);
            state[7] ^= (byte)((k >> 16) & 0xFF);
            state[11] ^= (byte)((k >> 08) & 0xFF);
            state[15] ^= (byte)((k >> 00) & 0xFF);

            // ROUND 1

            column = T1[state[0]] ^ T2[state[5]] ^ T3[state[10]] ^ T4[state[15]];
            column ^= roundKey[4];
            state[0] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[6]] ^ T3[state[11]] ^ T4[state[12]];
            column ^= roundKey[5];
            state[1] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[7]] ^ T3[state[8]] ^ T4[state[13]];
            column ^= roundKey[6];
            state[2] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[4]] ^ T3[state[9]] ^ T4[state[14]];
            column ^= roundKey[7];
            state[3] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);

            // ROUND 2

            column = T1[state[0]] ^ T2[state[6]] ^ T3[state[8]] ^ T4[state[14]];
            column ^= roundKey[8];
            state[0] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[7]] ^ T3[state[9]] ^ T4[state[15]];
            column ^= roundKey[9];
            state[1] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[4]] ^ T3[state[10]] ^ T4[state[12]];
            column ^= roundKey[10];
            state[2] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[5]] ^ T3[state[11]] ^ T4[state[13]];
            column ^= roundKey[11];
            state[3] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);

            // ROUND 3

            column = T1[state[0]] ^ T2[state[7]] ^ T3[state[10]] ^ T4[state[13]];
            column ^= roundKey[12];
            state[0] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[4]] ^ T3[state[11]] ^ T4[state[14]];
            column ^= roundKey[13];
            state[1] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[5]] ^ T3[state[8]] ^ T4[state[15]];
            column ^= roundKey[14];
            state[2] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[6]] ^ T3[state[9]] ^ T4[state[12]];
            column ^= roundKey[15];
            state[3] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);

            // ROUND 4

            column = T1[state[0]] ^ T2[state[4]] ^ T3[state[8]] ^ T4[state[12]];
            column ^= roundKey[16];
            state[0] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[5]] ^ T3[state[9]] ^ T4[state[13]];
            column ^= roundKey[17];
            state[1] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[6]] ^ T3[state[10]] ^ T4[state[14]];
            column ^= roundKey[18];
            state[2] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[7]] ^ T3[state[11]] ^ T4[state[15]];
            column ^= roundKey[19];
            state[3] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);

            // ROUND 5

            column = T1[state[0]] ^ T2[state[5]] ^ T3[state[10]] ^ T4[state[15]];
            column ^= roundKey[20];
            state[0] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[6]] ^ T3[state[11]] ^ T4[state[12]];
            column ^= roundKey[21];
            state[1] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[7]] ^ T3[state[8]] ^ T4[state[13]];
            column ^= roundKey[22];
            state[2] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[4]] ^ T3[state[9]] ^ T4[state[14]];
            column ^= roundKey[23];
            state[3] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);

            // ROUND 6

            column = T1[state[0]] ^ T2[state[6]] ^ T3[state[8]] ^ T4[state[14]];
            column ^= roundKey[24];
            state[0] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[7]] ^ T3[state[9]] ^ T4[state[15]];
            column ^= roundKey[25];
            state[1] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[4]] ^ T3[state[10]] ^ T4[state[12]];
            column ^= roundKey[26];
            state[2] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[5]] ^ T3[state[11]] ^ T4[state[13]];
            column ^= roundKey[27];
            state[3] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);

            // ROUND 7

            column = T1[state[0]] ^ T2[state[7]] ^ T3[state[10]] ^ T4[state[13]];
            column ^= roundKey[28];
            state[0] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[4]] ^ T3[state[11]] ^ T4[state[14]];
            column ^= roundKey[29];
            state[1] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[5]] ^ T3[state[8]] ^ T4[state[15]];
            column ^= roundKey[30];
            state[2] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[6]] ^ T3[state[9]] ^ T4[state[12]];
            column ^= roundKey[31];
            state[3] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);

            // ROUND 8

            column = T1[state[0]] ^ T2[state[4]] ^ T3[state[8]] ^ T4[state[12]];
            column ^= roundKey[32];
            state[0] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[5]] ^ T3[state[9]] ^ T4[state[13]];
            column ^= roundKey[33];
            state[1] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[6]] ^ T3[state[10]] ^ T4[state[14]];
            column ^= roundKey[34];
            state[2] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[7]] ^ T3[state[11]] ^ T4[state[15]];
            column ^= roundKey[35];
            state[3] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);

            // ROUND 9

            column = T1[state[0]] ^ T2[state[5]] ^ T3[state[10]] ^ T4[state[15]];
            column ^= roundKey[36];
            state[0] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = T1[state[1]] ^ T2[state[6]] ^ T3[state[11]] ^ T4[state[12]];
            column ^= roundKey[37];
            state[1] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = T1[state[2]] ^ T2[state[7]] ^ T3[state[8]] ^ T4[state[13]];
            column ^= roundKey[38];
            state[2] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);
            column = T1[state[3]] ^ T2[state[4]] ^ T3[state[9]] ^ T4[state[14]];
            column ^= roundKey[39];
            state[3] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);

            // LAST ROUND

            state[0] = sbox[state[0]];
            state[1] = sbox[state[1]];
            state[2] = sbox[state[2]];
            state[3] = sbox[state[3]];
            state[4] = sbox[state[4]];
            state[5] = sbox[state[5]];
            state[6] = sbox[state[6]];
            state[7] = sbox[state[7]];
            state[8] = sbox[state[8]];
            state[9] = sbox[state[9]];
            state[10] = sbox[state[10]];
            state[11] = sbox[state[11]];
            state[12] = sbox[state[12]];
            state[13] = sbox[state[13]];
            state[14] = sbox[state[14]];
            state[15] = sbox[state[15]];
            column = ((uint)state[0] << 24) | ((uint)state[6] << 16) | ((uint)state[8] << 08) | ((uint)state[14] << 00);
            column ^= roundKey[40];
            state[0] = (byte)(column >> 24);
            state[6] = (byte)(column >> 16);
            state[8] = (byte)(column >> 08);
            state[14] = (byte)(column >> 00);
            column = ((uint)state[1] << 24) | ((uint)state[7] << 16) | ((uint)state[9] << 08) | ((uint)state[15] << 00);
            column ^= roundKey[41];
            state[1] = (byte)(column >> 24);
            state[7] = (byte)(column >> 16);
            state[9] = (byte)(column >> 08);
            state[15] = (byte)(column >> 00);
            column = ((uint)state[2] << 24) | ((uint)state[4] << 16) | ((uint)state[10] << 08) | ((uint)state[12] << 00);
            column ^= roundKey[42];
            state[2] = (byte)(column >> 24);
            state[4] = (byte)(column >> 16);
            state[10] = (byte)(column >> 08);
            state[12] = (byte)(column >> 00);
            column = ((uint)state[3] << 24) | ((uint)state[5] << 16) | ((uint)state[11] << 08) | ((uint)state[13] << 00);
            column ^= roundKey[43];
            state[3] = (byte)(column >> 24);
            state[5] = (byte)(column >> 16);
            state[11] = (byte)(column >> 08);
            state[13] = (byte)(column >> 00);

            // WRITE OUTPUT

            output[0] = state[0];
            output[1] = state[6];
            output[2] = state[8];
            output[3] = state[14];
            output[4] = state[1];
            output[5] = state[7];
            output[6] = state[9];
            output[7] = state[15];
            output[8] = state[2];
            output[9] = state[4];
            output[10] = state[10];
            output[11] = state[12];
            output[12] = state[3];
            output[13] = state[5];
            output[14] = state[11];
            output[15] = state[13];

        }


        /* --------------------------------------------------
         * END OF ALGORITHM
         * TOOLS
         * 
         */
    }
}
