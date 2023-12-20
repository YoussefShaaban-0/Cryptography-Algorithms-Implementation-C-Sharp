using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
		public override string Decrypt(string cipherText, string key)
		{
			int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

			int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

			int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
			int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
			int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
			int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
			int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
			int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
			int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
			int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

			int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

			int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

			int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

			int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


			string bicipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
			string bikey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

			string Lm = "";
			string Rm = "";

			for (int i = 0; i < bicipher.Length / 2; i++)
			{
				Lm = Lm + bicipher[i];
				Rm = Rm + bicipher[i + bicipher.Length / 2];
			}

			//premutate key by pc-1
			string tmpk = "";
			List<string> C = new List<string>();
			List<string> D = new List<string>();

			for (int i = 0; i < 8; i++)
			{
				for (int j = 0; j < 7; j++)
				{
					tmpk = tmpk + bikey[PC_1[i, j] - 1];
				}
			}

			//C and D
			string c = tmpk.Substring(0, 28);
			string d = tmpk.Substring(28, 28);

			string temp = "";
			for (int i = 0; i <= 16; i++)
			{
				C.Add(c);
				D.Add(d);
				temp = "";
				if (i == 0 || i == 1 || i == 8 || i == 15)
				{
					temp = temp + c[0];
					c = c.Remove(0, 1);
					c = c + temp;
					temp = "";
					temp = temp + d[0];
					d = d.Remove(0, 1);
					d = d + temp;
				}

				else
				{
					temp = temp + c.Substring(0, 2);
					c = c.Remove(0, 2);
					c = c + temp;
					temp = "";
					temp = temp + d.Substring(0, 2);
					d = d.Remove(0, 2);
					d = d + temp;
				}
			}

			List<string> keys = new List<string>();
			for (int i = 0; i < D.Count; i++)
			{
				keys.Add(C[i] + D[i]);
			}

			//k1 --> k16 by pc-2
			List<string> nkeys = new List<string>();
			for (int k = 1; k < keys.Count; k++)
			{
				tmpk = "";
				temp = "";
				temp = keys[k];
				for (int i = 0; i < 8; i++)
				{
					for (int j = 0; j < 6; j++)
					{
						tmpk = tmpk + temp[PC_2[i, j] - 1];
					}
				}

				nkeys.Add(tmpk);
			}

			//premutation by IP for plain text
			string ip = "";
			for (int i = 0; i < 8; i++)
			{
				for (int j = 0; j < 8; j++)
				{
					ip = ip + bicipher[IP[i, j] - 1];
				}
			}

			List<string> L = new List<string>();
			List<string> R = new List<string>();

			string l = ip.Substring(0, 32);
			string r = ip.Substring(32, 32);

			L.Add(l);
			R.Add(r);
			string x = "";
			string h = "";

			string ebit = "";
			string exork = "";
			List<string> sbox = new List<string>();
			//string sb = "";
			string t = "";
			int row = 0;
			int col = 0;
			string tsb = "";
			string pp = "";
			string lf = "";

			for (int i = 0; i < 16; i++)
			{
				L.Add(r);
				exork = "";
				ebit = "";
				lf = "";
				pp = "";
				sbox.Clear();
				tsb = "";
				col = 0;
				row = 0;
				t = "";
				for (int j = 0; j < 8; j++)
				{
					for (int k = 0; k < 6; k++)
					{
						ebit = ebit + r[EB[j, k] - 1];
					}
				}

				for (int g = 0; g < ebit.Length; g++)
				{
					exork = exork + (nkeys[nkeys.Count - 1 - i][g] ^ ebit[g]).ToString();
				}

				for (int z = 0; z < exork.Length; z = z + 6)
				{
					t = "";
					for (int y = z; y < 6 + z; y++)
					{
						if (6 + z <= exork.Length)
							t = t + exork[y];
					}

					sbox.Add(t);
				}

				t = "";
				int sb = 0;
				for (int s = 0; s < sbox.Count; s++)
				{
					t = sbox[s];
					x = t[0].ToString() + t[5];
					h = t[1].ToString() + t[2] + t[3] + t[4];

					row = Convert.ToInt32(x, 2);
					col = Convert.ToInt32(h, 2);
					if (s == 0)
						sb = s1[row, col];

					if (s == 1)
						sb = s2[row, col];

					if (s == 2)
						sb = s3[row, col];

					if (s == 3)
						sb = s4[row, col];

					if (s == 4)
						sb = s5[row, col];

					if (s == 5)
						sb = s6[row, col];

					if (s == 6)
						sb = s7[row, col];

					if (s == 7)
						sb = s8[row, col];

					tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
				}

				x = "";
				h = "";

				for (int k = 0; k < 8; k++)
				{
					for (int j = 0; j < 4; j++)
					{
						pp = pp + tsb[P[k, j] - 1];
					}
				}

				for (int k = 0; k < pp.Length; k++)
				{
					lf = lf + (pp[k] ^ l[k]).ToString();
				}

				r = lf;
				l = L[i + 1];
				R.Add(r);
			}

			string r16l16 = R[16] + L[16];
			string ciphertxt = "";
			for (int i = 0; i < 8; i++)
			{
				for (int j = 0; j < 8; j++)
				{
					ciphertxt = ciphertxt + r16l16[IP_1[i, j] - 1];
				}
			}
			string pt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
			return pt;
		}

		public override string Encrypt(string plainText, string key)
		{

			plainText = plainText.Substring(2);
			key = key.Substring(2);
			char[] hex = new char[16] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
			string[] bin = new string[16] { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111" };
			string[] bin_key = new string[16];
			for (int i = 0; i < 16; i++)
			{
				for (int j = 0; j < 16; j++)
				{
					if (key[i] == hex[j])
					{
						bin_key[i] = bin[j];

					}
				}
			}
			string permuted_key;
			permuted_key = string.Concat(bin_key);
			int[] IP_arr = new int[56] { 57, 49 ,41 ,33, 25, 17, 9,1 ,58 ,50 ,42, 34, 26, 18,10, 2 ,59 ,51 ,43 ,35 ,27,19 ,11 ,3 ,60 ,52 ,44 ,36,
					63, 55 ,47 ,39, 31, 23, 15,7 ,62 ,54, 46 ,38 ,30 ,22,14 ,6 ,61 ,53 ,45 ,37 ,29,21, 13, 5 ,28 ,20 ,12, 4};

			char[] permuted_key_2 = new char[56];
			string C0;
			string D0;
			char[] C_0 = new char[28];
			char[] D_0 = new char[28];
			int m = 0;
			for (int i = 0; i < 56; i++)
			{
				int x = IP_arr[i] - 1;
				permuted_key_2[i] = permuted_key[x];
				if (i < 28)
					C_0[i] = permuted_key_2[i];
				else if (i < 56)
				{

					D_0[m] = permuted_key_2[i];
					m++;
				}
			}
			C0 = string.Concat(C_0);
			D0 = string.Concat(D_0);

			string[,] pre_key = new string[17, 2];
			pre_key[0, 0] = C0;
			pre_key[0, 1] = D0;

			for (int i = 1; i <= 16; i++)
			{
				if (i == 1 || i == 2 || i == 9 || i == 16)
				{


					string C;
					string D;
					C = pre_key[i - 1, 0];
					D = pre_key[i - 1, 1];
					string Cn;
					string Dn;
					char[] C_n = new char[28];
					char[] D_n = new char[28];
					for (int k = 1; k <= 28; k++)
					{

						if (k == 28)
						{
							C_n[k - 1] += C[0];
							D_n[k - 1] += D[0];
						}
						else if (k < 28)
						{
							C_n[k - 1] += C[k];
							D_n[k - 1] += D[k];
						}
					}
					Cn = string.Concat(C_n);
					Dn = string.Concat(D_n);
					pre_key[i, 0] = Cn;
					pre_key[i, 1] = Dn;

				}
				else
				{
					string C;
					string D;
					C = pre_key[i - 1, 0];
					D = pre_key[i - 1, 1];
					string Cn;
					string Dn;
					char[] C_n = new char[28];
					char[] D_n = new char[28];
					for (int k = 2; k <= 29; k++)
					{

						if (k == 28)
						{
							C_n[k - 2] += C[0];
							C_n[k - 1] += C[1];
							D_n[k - 2] += D[0];
							D_n[k - 1] += D[1];
						}
						else if (k < 28)
						{
							C_n[k - 2] += C[k];
							D_n[k - 2] += D[k];
						}
					}
					Cn = string.Concat(C_n);
					Dn = string.Concat(D_n);
					pre_key[i, 0] = Cn;
					pre_key[i, 1] = Dn;

				}
			}

			/*for (int i = 0; i <= 16; i++)
			{
				for (int j = 0; j < 2; j++)
					cout << pre_key[i][j] << "\t";
				cout << endl;
			}*/
			string[] pre_key_all = new string[16];
			for (int i = 0; i < 16; i++)
			{
				pre_key_all[i] = pre_key[i + 1, 0];
				pre_key_all[i] += pre_key[i + 1, 1];
			}

			string[] keys = new string[16];

			int[] pc_2 = new int[48] { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
			for (int i = 0; i < 16; i++)
			{
				string z;
				char[] z_ = new char[48];
				string y;
				for (int j = 0; j < 48; j++)
				{

					int x = pc_2[j] - 1;
					y = pre_key_all[i];
					z_[j] = y[x];
					//cout << z;

				}
				z = string.Concat(z_);
				keys[i] = z;
				//cout << keys[i]<<endl;
			}
			//كده خلصنا ال key
			string M;
			string[] M_ = new string[48];
			for (int i = 0; i < 16; i++)
			{
				for (int jj = 0; jj < 16; jj++)
				{
					if (plainText[i] == hex[jj])
					{
						//M += bin[j];
						M_[i] = bin[jj];
					}
				}
			}
			M = string.Concat(M_);
			//cout << M<<endl;
			int[] pc_msg = new int[64] { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
			string L0;
			string R0;
			char[] L0_ = new char[32];
			char[] R0_ = new char[32];
			int yy = 0;
			for (int i = 0; i < 64; i++)
			{
				if (i < 32)
					L0_[i] = M[pc_msg[i] - 1];
				else
				{
					R0_[yy] = M[pc_msg[i] - 1];
					yy++;
				}
			}
			L0 = string.Concat(L0_);
			R0 = string.Concat(R0_);
			int[] E_sel_table = new int[48] { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };


			string[] L = new string[17];
			string[] R = new string[17];
			L[0] = L0;
			R[0] = R0;
			int[,,] arrboxes = new int[8, 4, 16]  {{ { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },{0, 15, 7 ,4 ,14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },{4, 1 ,14, 8 ,13 ,6 ,2 ,11, 15, 12, 9 ,7, 3 ,10, 5, 0 },{15 ,12, 8 ,2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13} },
{{ 15, 1 ,8 ,14 ,6, 11, 3 ,4 ,9 ,7, 2 ,13, 12, 0, 5, 10 },{3 ,13 ,4, 7 ,15, 2 ,8 ,14, 12, 0 ,1 ,10, 6, 9 ,11, 5 }, {0 ,14 ,7, 11, 10, 4 ,13 ,1 ,5 ,8, 12, 6 ,9 ,3, 2, 15 },{13 ,8, 10, 1 ,3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
{ { 10, 0 ,9 ,14 ,6, 3, 15, 5 ,1 ,13, 12, 7, 11, 4, 2, 8 },{13, 7 ,0 ,9 ,3 ,4, 6 ,10 ,2 ,8, 5, 14, 12, 11, 15, 1 },{13, 6, 4, 9,  8 ,15 ,3,  0, 11, 1, 2, 12, 5, 10, 14, 7 },{1 ,10 ,13, 0, 6 ,9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
{ { 7 ,13, 14, 3, 0 ,6 ,9 ,10, 1, 2 , 8 , 5 ,11 ,12, 4, 15 },{13,8,11, 5 ,6 ,15, 0,3 ,4, 7, 2, 12, 1 ,10, 14, 9 },{ 10, 6, 9 ,0 ,12, 11, 7 ,13, 15, 1 ,3, 14, 5, 2,  8, 4 },{ 3 ,15, 0, 6, 10 ,1 ,13 ,8, 9, 4, 5, 11, 12, 7, 2, 14 } },
{ { 2 ,12 ,4 , 1, 7, 10,11, 6, 8 ,5 , 3, 15, 13, 0, 14, 9 },{ 14,11,2 ,12,4 ,7, 13, 1, 5, 0, 15, 10, 3 ,9 ,8, 6 },{  4,  2, 1 ,11,10, 13, 7, 8,  15 ,9, 12, 5, 6, 3,  0 ,14 },{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
{ { 12, 1 ,10 ,15,9, 2, 6,  8, 0 ,13 ,3 ,4 , 14, 7, 5, 11 },{ 10,15,4 ,2 ,7 ,12, 9, 5, 6, 1, 13, 14, 0, 11, 3 ,8 },{ 9 ,14 ,15, 5 , 2  , 8 ,12, 3 ,7 , 0, 4 ,10, 1 ,13,11,6 },{4, 3, 2, 12, 9 ,5 ,15 ,10, 11, 14, 1, 7, 6, 0 ,8 ,13 } },
{ { 4, 11, 2 ,14 ,15,0, 8 ,13 ,3 ,12, 9, 7 , 5 ,10 ,6, 1 },{  13, 0,11,7 ,4 ,9, 1, 10,14,3 ,5, 12, 2, 15, 8 ,6 },{ 1, 4,  11,13, 12, 3 ,7 ,14 ,10 ,15 ,6 ,8 , 0 , 5 ,9, 2 },{6 ,11 ,13, 8, 1, 4 ,10 ,7 ,9 ,5 ,0 ,15, 14, 2, 3, 12 } },
{ { 13 ,2 ,8 ,4 , 6 ,15,11, 1, 10, 9 ,3 ,14 ,5 ,0 ,12, 7 },{  1, 15,13,8 ,10,3 ,7 ,4, 12,5, 6, 11, 0 ,14 ,9 ,2 },{ 7, 11 ,4 ,1 , 9 ,12, 14, 2, 0,  6, 10 ,13, 15, 3, 5, 8 },{2, 1, 14, 7, 4, 10, 8, 13, 15,12, 9 ,0, 3, 5, 6 ,11 } }
};
			for (int i = 1; i <= 16; i++)
			{
				L[i] = R[i - 1];
				string x = R[i - 1];
				string ER;
				char[] ER_ = new char[48];
				for (int n = 0; n < 48; n++)
				{

					//	ER += x[E_sel_table[n] - 1];
					ER_[n] = x[E_sel_table[n] - 1];
				}
				ER = string.Concat(ER_);
				string xoR;
				string[] xoR_ = new string[48];
				for (int n = 0; n < 48; n++)
				{
					if (ER[n] == keys[i - 1][n])
					{
						xoR_[n] = "0";
					}
					else
						xoR_[n] = "1";

				}
				xoR = string.Concat(xoR_);
				// s boxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
				//int num0 = stoi(xoR);
				//cout << ER <<"er" << endl;
				//break;
				//string s_box;
				int[] dec_xbox = new int[8];
				int j = 0;
				for (int iii = 0; iii < 48; iii += 6) //<48
				{

					int k = 0;
					int rem = 0;
					int num0_dec = 0;
					int num1_dec = 0; ;
					string row;
					string col;
					char[] row_ = new char[2];
					char[] col_ = new char[4];
					//row += xoR[iii];
					//row += xoR[iii + 5];
					row_[0] = xoR[iii];
					row_[1] = xoR[iii + 5];
					row = string.Concat(row_);

					int num0 = Int32.Parse(row);
					col_[0] = xoR[iii + 1];
					col_[1] = xoR[iii + 2];
					col_[2] = xoR[iii + 3];
					col_[3] = xoR[iii + 4];
					col = string.Concat(col_);
					int num1 = Int32.Parse(col);
					while (num0 != 0)
					{
						double pow_ab = Math.Pow(2, k);
						int ress1 = Convert.ToInt32(pow_ab);
						rem = num0 % 10;
						num0 /= 10;
						num0_dec += rem * ress1;
						++k;
					}
					k = 0;
					rem = 0;
					while (num1 != 0)
					{
						double pow_ab = Math.Pow(2, k);
						int ress2 = Convert.ToInt32(pow_ab);
						rem = num1 % 10;
						num1 /= 10;
						num1_dec += rem * ress2;
						++k;
					}
					dec_xbox[j] = arrboxes[j, num0_dec, num1_dec];
					j++;
				}
				string after_xbox;
				string[,] after_xbox_ = new string[8, 4];
				string[] after_xbox_1d = new string[32];
				int u = 0;
				for (int xx = 0; xx < 8; xx++)
				{
					int zz = dec_xbox[xx];
					int[] a = new int[4] { 0, 0, 0, 0 };
					for (int ii = 0; zz > 0; ii++)
					{
						a[ii] = zz % 2;
						zz = zz / 2;
						//after_xbox += to_string(a[ii]);

					}
					for (int ii = 0; ii < 4; ii++)
					{
						after_xbox_[xx, ii] = a[3 - ii].ToString();
						after_xbox_1d[u] = after_xbox_[xx, ii];
						u++;
					}

				}

				//after_xbox = string.Concat(after_xbox_);

				int[] last_pc = new int[32] { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
				string fun;
				string[] fun_ = new string[32];

				for (int iii = 0; iii < 32; iii++)
				{


					fun_[iii] = after_xbox_1d[last_pc[iii] - 1];


				}
				fun = string.Concat(fun_);

				//break;
				//cout << fun<<"\t"<<after_xbox;

				for (int h = 0; h < 32; h++)
				{
					if (fun[h] == L[i - 1][h])
					{
						R[i] += "0";
					}
					else
						R[i] += "1";


				}
				//cout << endl;
				//cout << R[i] << "rrr" << endl;
				//	break;
			}
			//cout << R[16] << "rrr" << endl;
			//cout << L[16] << "rrr" << endl;
			string cipher = R[16] + L[16];
			//cout << cipher;
			int[] pcLast = new int[64] { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
			string last_cipher;
			char[] last_cipher_ = new char[64];
			for (int d = 0; d < 64; d++)
			{

				last_cipher_[d] = cipher[pcLast[d] - 1];

			}
			last_cipher = string.Concat(last_cipher_);

			//cout << cipher<<endl<< last_cipher;
			string cipher_hex;
			char[] cipher_hex_ = new char[16];
			int kkk = 0;
			for (int i = 0; i < 64; i += 4)
			{
				string x;
				char[] x_ = new char[4];
				x_[0] = last_cipher[i];
				x_[1] = last_cipher[i + 1];
				x_[2] = last_cipher[i + 2];
				x_[3] = last_cipher[i + 3];
				x = string.Concat(x_);

				for (int j = 0; j < 16; j++)
				{
					if (x == bin[j])
					{
						cipher_hex_[kkk] = hex[j];
						kkk++;
					}
				}

			}
			cipher_hex = string.Concat(cipher_hex_);
			cipher_hex = "0x" + cipher_hex;
			return cipher_hex;
		}
	}
}