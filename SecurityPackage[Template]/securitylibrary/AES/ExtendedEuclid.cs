using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        /// 

        public static long GCD(long A, long B)
        {
            if (B == 0)
            {
                return A;
            }
            var R = A % B;
            A = B;
            B = R;
            return GCD(A, B);
        }




        public int GetMultiplicativeInverse(int number, int baseN)
        {                                  // 23(inv)     mod    26 

            //check gcd if eq 1
            if (GCD(number, baseN) != 1)
            {
                //no mul. inv
                return -1;
            }
            else
            {
                int a1 = 1, a2 = 0, a3 = baseN;
                int b1 = 0, b2 = 1, b3 = number;

                int q;
                while (b3 != 1)
                {
                    q = a3 / b3;
                    int T1 = (a1 - (q * b1)), T2 = (a2 - (q * b2)), T3 = (a3 - (q * b3));

                    a1 = b1;
                    a2 = b2;
                    a3 = b3;

                    b1 = T1;
                    b2 = T2;
                    b3 = T3;


                }
                while (b2 < 0)
                {
                    b2 += baseN;
                }
                return b2;

            }
            //throw new NotImplementedException();
        }

    }
}