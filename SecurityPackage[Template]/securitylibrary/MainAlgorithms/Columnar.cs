using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText) {
            cipherText = cipherText.Replace(" ", "");
            plainText = plainText.Replace(" ", "");
            cipherText = cipherText.ToLower();

            int key_count = 0;
            int key1;
            int key2;



            for (int i = 0; i < plainText.Length; i++)
            {
                if (cipherText[0] == plainText[i])
                {

                    for (int j = i + 1; j < plainText.Length; j++)
                    {
                        if (cipherText[1] == plainText[j])
                        {
                            key1 = j - i;
                            for (int k = j + 1; k < plainText.Length; k++)
                            {
                                if (cipherText[2] == plainText[k])
                                {
                                    key2 = k - j;

                                    if (key1 == key2)
                                    {
                                        key_count = key1;

                                    }
                                }
                            }

                            break;



                        }
                    }
                }


            }

            int numofrows = cipherText.Length / key_count;
            if (cipherText.Length % key_count != 0)
                numofrows++;

            int[] key = new int[key_count];
            int zzz = 1;
            int x5 = numofrows * key_count - plainText.Length;


            for (int i = 0; i < x5; i++)
            {
                plainText += "x";
                cipherText += "_";
            }


            int cipher_element = 0;
            while (cipher_element < numofrows * key_count)
            {
                bool found = false;
                for (int i = 0; i < key_count; i++)
                {
                    if (cipherText[cipher_element] == plainText[i])
                    {
                        if (cipherText[cipher_element + 1] == plainText[i + key_count])
                        {
                            if (cipherText[cipher_element + numofrows - 1] != plainText[i + (numofrows - 1) * key_count])
                            {

                                found = true;
                                cipherText = cipherText.Insert(cipher_element + numofrows - 1, "x");
                            }
                        }

                    }
                }
                if (found == true)
                {

                    cipher_element = cipher_element + numofrows;

                }
                else
                {
                    cipher_element = cipher_element + numofrows;
                }
            }

            for (int i = 0; i < cipherText.Length; i = i + numofrows)
            {
                for (int j = 0; j < key_count; j++)
                {
                    if (cipherText[i] == plainText[j])
                    {
                        if (cipherText[i + 1] == plainText[j + key_count])
                        {
                            key[j] = zzz;
                            zzz++;

                        }
                    }
                }

            }

            List<int> keys = key.OfType<int>().ToList();


            return keys;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.Replace(" ", "");
            int numof_rows = cipherText.Length / key.Count;
            int x2 = cipherText.Length % key.Count;
            if (x2 != 0)
            {
                numof_rows++;
            }
            int x1 = numof_rows * key.Count;


            char[] c_t_arr = new char[x1];
            for (int i = 0; i < x1; i++)
            {
                c_t_arr[i] = 'x';
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                c_t_arr[i] = cipherText[i];
            }


            char[] p_t_arr = new char[x1];
            int iii = 1;
            int key_index = 0;
            int k = 0;
            for (int i = 0; i < x1; i++)
            {

                for (int j = 0; j < key.Count; j++)
                {
                    if (iii == key[j])
                    {
                        key_index = j;

                    }
                }
                int counter = 0;
                counter = k * key.Count;
                p_t_arr[key_index + counter] = c_t_arr[i];
                k++;
                if (k >= numof_rows)
                {
                    k = 0;
                    iii++;
                }
            }
            string P_T = new string(p_t_arr);

            return P_T;
            // throw new NotImplementedException();
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //if we have a problem dont count space of p text
            plainText = plainText.Replace(" ", "");
            //char[] p_t_arr = plainText.ToCharArray();
            //char[] c_t_arr = plainText.ToCharArray();
            int numof_rows = plainText.Length / key.Count;
            int x2 = plainText.Length % key.Count;
            if (x2 != 0)
            {
                numof_rows++;
            }


            int x1 = numof_rows * key.Count;
            char[] p_t_arr = new char[x1];
            char[] c_t_arr = new char[x1];
            for (int i = 0; i < x1; i++)
            {
                p_t_arr[i] = 'x';
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                p_t_arr[i] = plainText[i];


            }
            int iii = 1;
            int key_index = 0;
            int k = 0;
            for (int i = 0; i < x1; i++)
            {
                // int key_index = key.IndexOf(iii);
                for (int j = 0; j < key.Count; j++)
                {
                    if (iii == key[j])
                    {
                        key_index = j;

                    }
                }
                int counter = 0;
                counter = k * key.Count;
                c_t_arr[i] = p_t_arr[key_index + counter];
                k++;
                if (k >= numof_rows)
                {
                    k = 0;
                    iii++;
                }
            }




            string C_T = new string(c_t_arr);


            return C_T;
            // throw new NotImplementedException();
            //throw new NotImplementedException();
        }
    }
}
