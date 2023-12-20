using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    class AES1
    {
        int[,] S_box = new int[16, 16] {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
        };

        int Rcon_ind = 0;
        int[,] Rcon = new int[4, 10] {
            {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
        int[,] galois_Field_mixMat = new int[4, 4] {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}};
        int[,] matrix_keys_of_rounds = new int[4, 44];


       


        public  string Encrpt(string plainText, string key)
        {
            //state
            int[,] rounded_plain = Matrix_plain(plainText); //array 4*4 of plaintext
            Matrix_key(key); //array 4*4 of key

            //schedule key
            key_round_to_start(); //10 round 44col

            rounded_plain = initial_round(rounded_plain);

            for (int i = 0; i < 9; i++)
                rounded_plain = rounds(rounded_plain, i + 1, 0);

            rounded_plain = rounds(rounded_plain, 10, 1); //without mix

            string s = ConvertMatrixToString(rounded_plain);
            return s;
        }






        //round plaintext
        int[,] Matrix_plain(string plain_text)
        {
            int[,] matrix = new int[4, 4];
            int index = 2;
            //array 4*4
            //convert to int
            //each index contain 2 index of plaintext
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    matrix[j, i] = Convert.ToInt32(("0x" + plain_text[index++] + plain_text[index++]), 16); //store in col by col
            return matrix;
        }
        //round key
        void Matrix_key(string key)
        {
            //  int[,] arr = new int[4, 4];
            int IndexOfKey = 2;
            //array 4*4
            //convert to int
            //each index contain 2 index of plaintext
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    matrix_keys_of_rounds[j, i] = Convert.ToInt32(("0x" + key[IndexOfKey++] + key[IndexOfKey++]), 16);
        }
        void key_round_to_start()
        {
            int[] LastCol = new int[4];
            int[] FirstCol = new int[4];
            int[] ColRcon = new int[4];
            int[] res = new int[4];
            //last col i=4
            for (int i = 4; i < 44; i++) //col
            {
                for (int j = 0; j < 4; j++) //row
                {
                    //col3 
                    LastCol[j] = matrix_keys_of_rounds[j, i - 1];
                    //first col of matrix given key
                    FirstCol[j] = matrix_keys_of_rounds[j, i - 4];
                    //git col of rson 4*10
                    if (Rcon_ind < 10)
                        ColRcon[j] = Rcon[j, Rcon_ind];
                }

                //if index 4
                //do rotate col, subsitude and xor
                if (i % 4 == 0)
                {
                    LastCol = Rotation(LastCol);
                    LastCol = Substitude(LastCol);
                    res = xor(LastCol, FirstCol, ColRcon, true); //true i will xor 3col
                    Rcon_ind++;
                }
                else //false i will xor 2col
                    res = xor(LastCol, FirstCol, ColRcon, false); //last i calc xor second col,third... xor rson
                //add col to key
                for (int j = 0; j < 4; j++)
                {
                    matrix_keys_of_rounds[j, i] = res[j];
                }
            }
        }
        int[] Rotation(int[] col)
        {
            //swap
            int tmp = col[0];

            col[0] = col[1];
            col[1] = col[2];
            col[2] = col[3];

            /* for (int i = 0; i < 3; i++)
                 col[i] = col[i + 1];*/
            col[3] = tmp;
            return col;
        }
        int[] Substitude(int[] col)
        {
            int[] res = new int[4];
            //index row and col in sbox
            int rowSbox;
            int colSbox;
            for (int i = 0; i < 4; i++)
            {
                //convert to hexa
                string val = Convert.ToString(col[i], 16);
                if (val.Length == 1)
                {
                    rowSbox = 0;
                    //first ind of string
                    colSbox = Convert.ToInt32(val[0].ToString(), 16);
                }
                else
                {
                    //search in sbox string of 0 as row and 1 as col
                    rowSbox = Convert.ToInt32(val[0].ToString(), 16);
                    colSbox = Convert.ToInt32(val[1].ToString(), 16);
                }

                res[i] = S_box[rowSbox, colSbox];
            }
            return res;
        }
        int[] xor(int[] LastCol, int[] FirstCol, int[] col_rccon, bool is_divid_4)
        {
            int[] res = new int[4];
            for (int i = 0; i < 4; i++)
            {
                string val;
                //is 4 xor with 3col else 2col
                if (is_divid_4 == true)
                    val = Convert.ToString(LastCol[i] ^ FirstCol[i] ^ col_rccon[i], 16);
                else
                    val = Convert.ToString(LastCol[i] ^ FirstCol[i], 16);

                res[i] = Convert.ToInt32(val, 16);
            }
            return res;
        }
        int[,] initial_round(int[,] first_round_plain)
        {
            string val;
            int[,] res = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //xor rounded plain and rounded key
                    val = Convert.ToString(first_round_plain[j, i] ^ matrix_keys_of_rounds[j, i], 16);

                    res[j, i] = Convert.ToInt32(val, 16);
                }
            }
            return res;
        }



        /////////////////////////////////////////////////////// 

        int[,] rounds(int[,] arr, int num_of_round, int num_main_round)
        {
            arr = substitute_matrix_4_4(arr, 0);
            arr = shift_left(arr, 0); //0=>ecn
            if (num_main_round == 0)
                arr = mixCols(arr);
            arr = RoundKey(arr, num_of_round);
            return arr;
        }

        int[,] substitute_matrix_4_4(int[,] matrix, int num_of_box)
        {
            int[,] arr = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int value = matrix[i, j];
                    int I_sbox = value >> 4;
                    int j_sbox = value & 0x0F;
                    //if 0 is sbox else inverse
                    if (num_of_box == 0)
                        arr[i, j] = S_box[I_sbox, j_sbox];
                    /*  else
                          arr[i, j] = S_box_Inverse[I_sbox, j_sbox];*/
                }
            }
            return arr;
        }

        int[,] shift_left(int[,] mat, int inverse)
        {
            int[,] arr = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                int shiftAmount = (inverse == 0) ? i : (4 - i) % 4;
                for (int j = 0; j < 4; j++)
                {
                    arr[i, j] = mat[i, (j + shiftAmount) % 4];
                }
            }
            return arr;
        }

        int[,] mixCols(int[,] arrShifted)
        {
            int[,] mixedCols = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                int s0 = arrShifted[0, i];
                int s1 = arrShifted[1, i];
                int s2 = arrShifted[2, i];
                int s3 = arrShifted[3, i];

                int t = s0 ^ s1 ^ s2 ^ s3;

                int u = s0 ^ s1;
                u = multiply_Two(u);
                mixedCols[0, i] = u ^ t ^ s0;

                u = s1 ^ s2;
                u = multiply_Two(u);
                mixedCols[1, i] = u ^ t ^ s1;

                u = s2 ^ s3;
                u = multiply_Two(u);
                mixedCols[2, i] = u ^ t ^ s2;

                u = s3 ^ s0;
                u = multiply_Two(u);
                mixedCols[3, i] = u ^ t ^ s3;
            }
            return mixedCols;
        }

        int multiply_Two(int x)
        {
            int ret = (x << 1);
            if (ret > 0xFF)
            {
                ret ^= 0x1B;
            }
            return ret & 0xFF;
        }

        int[,] RoundKey(int[,] matrix, int Round_index)
        {
            int[,] key_round = GetKey(Round_index); // get 4x4 key for the current round
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // XOR the key with the matrix
                    key_round[i, j] ^= matrix[i, j];
                }
            }
            return key_round;
        }

        int[,] GetKey(int indexOfRound)
        {
            int[,] arr = new int[4, 4];
            int colIndex = indexOfRound * 4;
            for (int j = 0; j < 4; j++)
            {
                arr[j, 0] = matrix_keys_of_rounds[j, colIndex];
                arr[j, 1] = matrix_keys_of_rounds[j, colIndex + 1];
                arr[j, 2] = matrix_keys_of_rounds[j, colIndex + 2];
                arr[j, 3] = matrix_keys_of_rounds[j, colIndex + 3];
            }
            return arr;
        }

        string ConvertMatrixToString(int[,] arr)
        {
            StringBuilder str = new StringBuilder("0x", 34);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    str.Append(arr[j, i].ToString("X2"));
                }
            }
            return str.ToString();
        }


    }
}
