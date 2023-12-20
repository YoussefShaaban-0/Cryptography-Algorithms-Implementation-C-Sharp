using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] key = new char[26];
            cipherText = cipherText.ToLower();
            for (int i = 0; i < plainText.Length; i++) {
                int j;
                if (plainText[i] >= 65 && plainText[i] <= 90)
                    j = plainText[i] - 65;
                else
                    j = plainText[i] - 97;
                key[j] = cipherText[i];
            
            
            }
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            //char x=  alpha[4];
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 0)
                {

                    for (int j = 0; j < alpha.Length; j++)
                    {
                        if (!(key.Contains<char>(alpha[j])))
                        {
                            key[i] = alpha[j];
                            break;
                        }
                    }
                }
            }

            return new string(key);
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            char[] plainText = new char[cipherText.Length];
            if (!cipherText.Equals(cipherText.ToLower())) {
                cipherText = cipherText.ToLower();

            }
            for (int i=0;i<cipherText.Length;i++) {
                if (cipherText[i] == ' ') {
                    plainText[i] = ' ';
                }
                else
                {

                    plainText[i] =(char)(key.IndexOf(cipherText[i])+97);
                  
                }
            }
            return new string(plainText);

            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            char[] chiperText = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
               
                
                int j;
                if (plainText[i] >= 65 && plainText[i] <= 90)
                    j = plainText[i] - 65;
                else
                    j = plainText[i] - 97;
                    
                 
                chiperText[i]= key[j];
                
            }
            return new string(chiperText);
           // throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string distinct_value = new String(cipher.Distinct().ToArray());
            int[] countoffreq = new int[distinct_value.Length];
            char[] CharFrequency ={ 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h',
            'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w',
            'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };
            for (int i = 0; i < distinct_value.Length; i++)
            {
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (distinct_value[i] == cipher[j])
                    {
                        countoffreq[i]++;
                    }

                }

            }
            int[] countoffreq2 = new int[distinct_value.Length];
            for (int i = 0; i < distinct_value.Length; i++)
            {
                countoffreq2[i] = countoffreq[i];
            }
            string distinct_value2 = distinct_value;
            char[] charArr1 = distinct_value.ToCharArray();


            int ii = 0;
            for (int i = 0; i < countoffreq.Length; i++)
            {
                int maxfreq = countoffreq2.Max();
                int maxfreqindex = countoffreq2.ToList().IndexOf(maxfreq);
                //  distinct_value2[maxfreqindex] = CharFrequency[ii];
                charArr1[maxfreqindex] = CharFrequency[ii];
                ii++;
                countoffreq2[maxfreqindex] = 0;

            }
            //  string plain_text = cipher;
            char[] plain_text_arr = cipher.ToCharArray(); ;
            for (int i = 0; i < distinct_value.Length; i++)
            {
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (distinct_value[i] == cipher[j])
                    {
                        plain_text_arr[j] = charArr1[i];

                    }
                }
            }
            string plain_text = new string(plain_text_arr);

            return plain_text;
            //throw new NotImplementedException();
        }
    }
}