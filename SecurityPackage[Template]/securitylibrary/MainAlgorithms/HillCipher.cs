using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int m = Convert.ToInt32(Math.Sqrt((cipherText.Count)));
            List<int> Key = new List<int>();
            int[,] matrix_of_ciper = new int[m, cipherText.Count() / m];
            int[,] matrix_of_plain = new int[m, plainText.Count() / m];
            //fill matrix cipher
            for (int y = 0; y < plainText.Count; y++)
            {
                for (int j = 0; j < plainText.Count() / m; j++)
                {
                    for (int i = 0; i < m; i++)
                    {
                        matrix_of_plain[i, j] = plainText.ElementAt(y);
                        y++;
                    }
                }
            }
            // fill matrix plain text
            for (int y = 0; y < cipherText.Count; y++)
            {
                for (int j = 0; j < cipherText.Count() / m; j++)
                {
                    for (int i = 0; i < m; i++)
                    {
                        matrix_of_plain[i, j] = plainText.ElementAt(y);
                        y++;
                    }
                }
            }
            // find key 
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            Key = new List<int>(new[] { i, j, k, l });
                            List<int> aa = Encrypt(plainText, Key);
                            if (aa.SequenceEqual(cipherText))
                            {
                                return Key;
                            }

                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }

       

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = Convert.ToInt32(Math.Sqrt((key.Count())));
            int[,] matrix_of_key = new int[m, key.Count() / m];
            int[,] matrix_of_keyivn = new int[m, key.Count() / m];
            int[,] Transpose_Matrix = new int[m, key.Count() / m];
            List<int> plain = new List<int>();
            /// fill matrix of key
            /// 
            for (int y = 0; y < key.Count; y++)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < key.Count() / m; j++)
                    {
                        matrix_of_key[i, j] = key.ElementAt(y);
                        y++;
                    }
                }
            }
            // have matrix of key and cipher text
            // find det(k)
            int det = 0;
            if (m == 2)
            {
                det = matrix_of_key[0, 0] * matrix_of_key[1, 1] -
                     matrix_of_key[1, 0] * matrix_of_key[0, 1];
                det = det % 26;
                while (det < 0)
                {
                    det = det + 26;
                }
                if (det == 6) {
                    throw new SystemException();
                }
                var tmp = matrix_of_key[1, 1];
                matrix_of_key[1, 1] = matrix_of_key[0, 0];
                matrix_of_key[0, 0] = tmp;
                matrix_of_key[0, 1] *= -1;
                matrix_of_key[1, 0] *= -1;
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < key.Count() / m; j++)
                    {
                        
                        matrix_of_key[i, j] *= det;
                        matrix_of_key[i, j] = matrix_of_key[i, j] % 26;
                        while (matrix_of_key[i, j] < 0)
                        {
                            matrix_of_key[i, j] += 26;
                        }


                    }
                }
                // matrix of key now * matrix of cipher
                int[,] matrix_OF_cipher = new int[m, cipherText.Count() / 2];

                for (int y = 0; y < cipherText.Count; y++)
                {
                    for (int j = 0; j < cipherText.Count() / m; j++)
                    {
                        for (int i = 0; i < m; i++)
                        {
                            matrix_OF_cipher[i, j] = cipherText.ElementAt(y);
                            y++;
                        }
                    }
                }
                int sum1 = 0;
                for (int colm = 0; colm < cipherText.Count() / m; colm++)
                {
                    for (int i = 0; i < m; i++)
                    {
                        for (int j = 0; j < m; j++)
                        {
                            sum1 += matrix_of_key[i, j] * matrix_OF_cipher[j, colm];
                        }
                        plain.Add(sum1 % 26);
                        sum1 = 0;
                    }
                }

                return plain;
            }

            //det3*3(k)
            
            for (int i = 0; i < 3; i++)
                det = det + (matrix_of_key[0, i] * (matrix_of_key[1, (i + 1) % 3] * matrix_of_key[2, (i + 2) % 3] - matrix_of_key[1, (i + 2) % 3] * matrix_of_key[2, (i + 1) % 3]));
            det = det % 26;
            while (det < 0)
            {
                det += 26;
            }

            int b;
            int c;

            var q = (26 + 1);

            while (q % (26 - det) != 0)
            {
                q += 26;
            }
            c = q / (26 - det);
            b = (26 - c);

            // fill matrix of k inverse before transpose

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if (i == j)
                    {
                        int k0 =
                            (matrix_of_key[(i + 1) % 3, (j + 1) % 3] * matrix_of_key[(i + 2) % 3, (j + 2) % 3]) -
                            (matrix_of_key[(i + 1) % 3, (j + 2) % 3] * matrix_of_key[(i + 2) % 3, (j + 1) % 3]);
                        k0 %= 26;
                        while (k0 < 0)
                        {
                            k0 += 26;
                        }
                        int x = Convert.ToInt32(k0 * b * Math.Pow(-1, (j + i)));
                        x %= 26;
                        while (x < 0)
                        {
                            x += 26;
                        }
                        matrix_of_keyivn[i, j] = x;

                    }
                    else if ((i == 0 && j == 2) || (i == 2 && j == 0))
                    {
                        int k2 = (matrix_of_key[(i + 1) % 3, (j + 1) % 3] * matrix_of_key[(i + 2) % 3, (j + 2) % 3]) -
                                    (matrix_of_key[(i + 1) % 3, (j + 2) % 3] * matrix_of_key[(i + 2) % 3, (j + 1) % 3]);
                        k2 %= 26;
                        while (k2 < 0)
                        {
                            k2 += 26;
                        }
                        int x1 = Convert.ToInt32(k2 * b * Math.Pow(-1, (j + i)));
                        x1 %= 26;
                        while (x1 < 0)
                        {
                            x1 += 26;
                        }
                        matrix_of_keyivn[i, j] = x1;
                    }
                    else
                    {
                        int k = (matrix_of_key[(i + 1) % 3, (j + 2) % 3] * matrix_of_key[(i + 2) % 3, (j + 1) % 3]) -
                            (matrix_of_key[(i + 1) % 3, (j + 1) % 3] * matrix_of_key[(i + 2) % 3, (j + 2) % 3]);
                        k %= 26;
                        while (k < 0)
                        {
                            k += 26;
                        }
                        int x2 = Convert.ToInt32(k * b * Math.Pow(-1, (j + i)));
                        x2 %= 26;
                        while (x2 < 0)
                        {
                            x2 += 26;
                        }
                        matrix_of_keyivn[i, j] = x2;

                    }


                }
            }
            //transpose matrix.......
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    Transpose_Matrix[j, i] = matrix_of_keyivn[i, j];

                }
            }



            //get matrix of cipher text
            int[,] matrix_OF_Cipher = new int[m, cipherText.Count() / 2];

            for (int y = 0; y < cipherText.Count; y++)
            {
                for (int j = 0; j < cipherText.Count() / m; j++)
                {
                    for (int i = 0; i < m; i++)
                    {
                        matrix_OF_Cipher[i, j] = cipherText.ElementAt(y);
                        y++;
                    }
                }
            }
            //finally multiply transpose matrix * cipher text matrix
            int sum = 0;
            for (int colm = 0; colm < cipherText.Count() / m; colm++)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        sum += Transpose_Matrix[i, j] * matrix_OF_Cipher[j, colm];
                    }
                    plain.Add(sum % 26);
                    sum = 0;
                }
            }
            return plain;         
        }

     

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = Convert.ToInt32(Math.Sqrt((key.Count())));
            int[,] matrix_of_key = new int[m, key.Count() / m];
            List<int> ciper = new List<int>();
            /// fill matrix of key
            for (int y = 0; y < key.Count; y++)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < key.Count() / m; j++)
                    {
                        matrix_of_key[i, j] = key.ElementAt(y);
                        y++;
                    }
                }
            }
            // fil matrix of plain text
            int[,] matrix_OF_Plain = new int[m, plainText.Count() / 2];

            for (int y = 0; y < plainText.Count; y++)
            {
                for (int j = 0; j < plainText.Count() / m; j++)
                {
                    for (int i = 0; i < m; i++)
                    {
                        matrix_OF_Plain[i, j] = plainText.ElementAt(y);
                        y++;
                    }
                }
            }
            int sum = 0;
            for (int colm = 0; colm < plainText.Count() / m; colm++)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        sum += matrix_of_key[i, j] * matrix_OF_Plain[j, colm];
                    }
                    ciper.Add(sum % 26);
                    sum = 0;
                }
            }

            return ciper;
            //throw new NotImplementedException();
        }

     

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int m = Convert.ToInt32(Math.Sqrt((plain3.Count())));
            int[,] matrix_of_plain = new int[m, plain3.Count() / m];
            int[,] Transpose_Matrix = new int[m, plain3.Count() / m];

            List<int> key = new List<int>();
            /// fill matrix of plain
            /// 
            for (int i = 0; i < plain3.Count(); i++)
            {
                for (int t = 0; t < (plain3.Count() / m); t++)
                {
                    for (int r = 0; r < m; r++)
                    {
                        matrix_of_plain[r, t] = plain3.ElementAt(i);
                        i++;
                    }
                }
            }
           
            

            int det = 0;

            for (int i = 0; i < 3; i++)
                det = det + (matrix_of_plain[0, i] * (matrix_of_plain[1, (i + 1) % 3] * matrix_of_plain[2, (i + 2) % 3] - matrix_of_plain[1, (i + 2) % 3] * matrix_of_plain[2, (i + 1) % 3]));
            det = det % 26;
            while (det < 0)
            {
                det += 26;
            }
            int b;
            int c;
            var q = (26 + 1);

            while (q % (26 - det) != 0)
            {
                q += 26;
            }
            c = q / (26 - det);
            b = (26 - c);
            
          


            int[,] matrix_of_plainivn = new int[m, plain3.Count() / m];
             // fill matrix of k inverse before transpose

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < plain3.Count() / m; j++)
                {
                    if (i == j)
                    {
                        int k0 =
                            (matrix_of_plain[(i + 1) % 3, (j + 1) % 3] * matrix_of_plain[(i + 2) % 3, (j + 2) % 3]) -
                            (matrix_of_plain[(i + 1) % 3, (j + 2) % 3] * matrix_of_plain[(i + 2) % 3, (j + 1) % 3]);
                        k0 %= 26;
                        while (k0 < 0)
                        {
                            k0 += 26;
                        }
                        int x = Convert.ToInt32(k0 * b * Math.Pow(-1, (j + i)));
                        x %= 26;
                        while (x < 0)
                        {
                            x += 26;
                        }
                        matrix_of_plainivn[i, j] = x;

                    }
                    else if ((i == 0 && j == 2) || (i == 2 && j == 0))
                    {
                        int k2 = (matrix_of_plain[(i + 1) % 3, (j + 1) % 3] * matrix_of_plain[(i + 2) % 3, (j + 2) % 3]) -
                                    (matrix_of_plain[(i + 1) % 3, (j + 2) % 3] * matrix_of_plain[(i + 2) % 3, (j + 1) % 3]);
                        k2 %= 26;
                        while (k2 < 0)
                        {
                            k2 += 26;
                        }
                        int x1 = Convert.ToInt32(k2 * b * Math.Pow(-1, (j + i)));
                        x1 %= 26;
                        while (x1 < 0)
                        {
                            x1 += 26;
                        }
                        matrix_of_plainivn[i, j] = x1;
                    }
                    else
                    {
                        int k = (matrix_of_plain[(i + 1) % 3, (j + 2) % 3] * matrix_of_plain[(i + 2) % 3, (j + 1) % 3]) -
                            (matrix_of_plain[(i + 1) % 3, (j + 1) % 3] * matrix_of_plain[(i + 2) % 3, (j + 2) % 3]);
                        k %= 26;
                        while (k < 0)
                        {
                            k += 26;
                        }
                        int x2 = Convert.ToInt32(k * b * Math.Pow(-1, (j + i)));
                        x2 %= 26;
                        while (x2 < 0)
                        {
                            x2 += 26;
                        }
                        matrix_of_plainivn[i, j] = x2;

                    }


                }
            }


              
            //transpose matrix.......
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    Transpose_Matrix[j, i] = matrix_of_plainivn[i, j];

                }
            }
            
            
            //get matrix of cipher text
            int[,] matrix_OF_Cipher = new int[m, (cipher3.Count) / m];
            //fil matrix col by col 
            for (int i = 0; i < cipher3.Count; i++)
            {
                for (int ci = 0; ci < (cipher3.Count() / m); ci++)
                {
                    for (int r = 0; r < m; r++)
                    {
                        matrix_OF_Cipher[r, ci] = cipher3.ElementAt(i);
                        i++;
                    }
                }
            }
            

            //finally multiply transpose matrix * cipher text matrix
            int sum = 0;


            for (int colm = 0; colm < plain3.Count() / m; colm++)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        sum += matrix_OF_Cipher[i, j] * Transpose_Matrix[j, colm];
                    }
                    key.Add(sum % 26);
                    sum = 0;
                }
            }
            int[,] matrix_OF_key = new int[m, (key.Count) / m];
            for (int o = 0; o < key.Count(); o++)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int x = 0; x < key.Count / m; x++)
                    {
                        matrix_OF_key[i, x] = key.ElementAt(o);
                        o++;
                    }
                }
            }


            List<int> key1 = new List<int>();
            for (int x = 0; x < key.Count / m; x++)
            {
                for (int i = 0; i < m; i++)
                {
                    key1.Add(matrix_OF_key[i, x]);
                }
            }
            return key1;
            //throw new NotImplementedException();
        }

      
    }
}
