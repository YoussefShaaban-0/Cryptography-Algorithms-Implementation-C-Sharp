using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {


            int pa = pow_clac(alpha, xa, q);
            int pb = pow_clac(alpha, xb, q);
            int secret_key1 = pow_clac(pb, xa, q);
            int secret_key2 = pow_clac(pa, xb, q);
       
            List<int> secret_key = new List<int>();
            secret_key.Add(secret_key1);
            secret_key.Add(secret_key2);

            return secret_key;
        }
        public int pow_clac(int p, int x, int q)
        {
            int result = 1;
            for (int i = 1; i <= x; i++)
            {
                result = (result * p) % q;

            }
            return result;
        }





    }
}