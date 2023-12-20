using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string s = string.Empty;
            int counter = 0;
            for (int k = 0; k < cipherText.Length - 1; k += 2)
            {
                s += cipherText[k];
                if (cipherText[k] == cipherText[k + 1])
                {
                    counter += 1;
                    s += 'X';
                    k -= 1;
                }
                else
                {
                    s += cipherText[k + 1];
                }
            }
            if ((s.Length - counter) < cipherText.Length)
            {
                s += cipherText[cipherText.Length - 1];
                s += 'X';
            }
            cipherText = s;
            char[] ptext = new char[cipherText.Length];
            for (int x = 0; x < cipherText.Length; x++)
            {
                ptext[x] = cipherText[x];
            }
            int[] arre = new int[4];
            char[,] A = new char[5, 5];


            int[] dicty = new int[26];

            for (int r = 0; r < key.Length; r++)
            {
                if (key[r] != 'J')
                {
                    dicty[key[r] - 65] = 2;

                }
            }
            dicty['J' - 65] = 1;

            int i = 0, j = 0;

            for (int k = 0; k < key.Length; k++)
            {
                if (dicty[key[k] - 65] == 2)
                {
                    dicty[key[k] - 65] -= 1;
                    A[i, j] = key[k];
                    j++;
                    if (j == 5)
                    {
                        i++;
                        j = 0;
                    }
                }
            }
            for (int k = 0; k < 26; k++)
            {
                if (dicty[k] == 0)
                {
                    A[i, j] = (char)(k + 65);
                    j++;
                    if (j == 5)
                    {
                        i++;
                        j = 0;
                    }
                }
            }

           
            List<string> tow = new List<string>();

            int o = 0;
            while (o < cipherText.Length)
            {
                if (o == cipherText.Length - 1)
                {
                    tow.Add(cipherText[o].ToString() + 'X');
                    break;
                }
                if (cipherText[o] == cipherText[o + 1])
                {
                    tow.Add(cipherText[o].ToString() + 'X');
                    o++;
                    continue;
                }

                char first = cipherText[o];
                char second = cipherText[o + 1];
                tow.Add(first.ToString() + second);
                o += 2; ;
            }
            int e = 0;
            int row1 = 0, row2 = 0, col1 = 0, col2 = 0;
            List<string> text = new List<string>();
            while (e < tow.Count())
            {
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        char y = A[row, col];
                        string element = tow[e];

                        if (element[0] == y)
                        {
                            row1 = row;
                            col1 = col;
                        }
                        if (element[1] == y)
                        {
                            row2 = row;
                            col2 = col;
                        }
                    }
                }
                if (col1 == col2)
                {
                    row1 = (row1 - 1);
                    row2 = (row2 - 1);
                    if (row1 == -1)
                    {
                        row1 = 4;
                    }
                    if (row2 == -1)
                        row2 = 4;
                    text.Add(A[row1, col2] + A[row2, col2].ToString());
                }
                else if (row1 == row2)
                {
                    col1 = (col1 - 1);
                    col2 = (col2 - 1);
                    if (col1 == -1)
                        col1 = 4;
                    if (col2 == -1)
                        col2 = 4;

                    text.Add(A[row1, col1] + A[row1, col2].ToString());
                }
                else
                {
                    text.Add(A[row1, col2] + A[row2, col1].ToString());
                }
                e++;
            }

            for (i = 0; i < text.Count; i++)
            {
                if (text[i].Contains("X"))
                {
                    if (text[i][1] == 'X')
                    {
                        if (!(i == text.Count - 1))
                        {
                            if (text[i][0] == text[i + 1][0])
                            {
                                text[i] = text[i][0].ToString();
                            }
                        }
                        else
                        {
                            text[i] = text[i][0].ToString();
                        }

                    }
                }
            }

            string plaintext = String.Join("", text);
            return plaintext.ToLower();
        }

        public  string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            string s = string.Empty;
            int counter = 0;
            for (int k = 0; k < plainText.Length - 1; k += 2)
            {
                s += plainText[k];
                if (plainText[k] == plainText[k + 1])
                {
                    counter += 1;
                    s += 'x';
                    k -= 1;
                }
                else
                {
                    s += plainText[k + 1];
                }
            }
            if ((s.Length - counter) < plainText.Length)
            {
                s += plainText[plainText.Length - 1];
                s += 'x';
            }
            plainText = s;
            char[] ptext = new char[plainText.Length];
            for (int x = 0; x < plainText.Length; x++)
            {
                ptext[x] = plainText[x];
            }
            int[] arre = new int[4];
            char[,] A = new char[5, 5];


            int[] dicty = new int[26];

            for (int r = 0; r < key.Length; r++)
            {
                if (key[r] != 'j')
                {
                    dicty[key[r] - 97] = 2;

                }
            }
            dicty['j' - 97] = 1;

            int i = 0, j = 0;

            for (int k = 0; k < key.Length; k++)
            {
                if (dicty[key[k] - 97] == 2)
                {
                    dicty[key[k] - 97] -= 1;
                    A[i, j] = key[k];
                    j++;
                    if (j == 5)
                    {
                        i++;
                        j = 0;
                    }
                }
            }
            for (int k = 0; k < 26; k++)
            {
                if (dicty[k] == 0)
                {
                    A[i, j] = (char)(k + 97);
                    j++;
                    if (j == 5)
                    {
                        i++;
                        j = 0;
                    }
                }
            }


            for (int z = 0; z < plainText.Length; z += 2)
            {

                char a = plainText[z], b = plainText[z + 1];
                if (a == 'j')
                {
                    a = 'i';
                }
                if (b == 'j')
                {
                    b = 'i';
                }
                for (int m = 0; m < 5; m++)
                {
                    for (int n = 0; n < 5; n++)
                    {
                        if (A[m, n] == a)
                        {
                            arre[0] = m;
                            arre[1] = n;
                        }
                        else if (A[m, n] == b)
                        {
                            arre[2] = m;
                            arre[3] = n;
                        }

                    }
                }

                if (arre[0] == arre[2])
                {
                    ptext[z] = A[arre[0], (arre[1] + 1) % 5];
                    ptext[z + 1] = A[arre[0], (arre[3] + 1) % 5];
                }
                else if (arre[1] == arre[3])
                {
                    ptext[z] = A[(arre[0] + 1) % 5, arre[1]];
                    ptext[z + 1] = A[(arre[2] + 1) % 5, arre[1]];
                }
                else
                {
                    ptext[z] = A[arre[0], arre[3]];
                    ptext[z + 1] = A[arre[2], arre[1]];
                }

            }
            string cipher = new string(ptext).ToUpper();
            return cipher; 
            // throw new NotImplementedException();
        }
    }
}