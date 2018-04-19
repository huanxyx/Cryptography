package main.java.cryptography.des;

import java.util.Random;

/**
 * DES加密
 * 
 * @author Huan
 *
 */
public class DES {

	//扩展表
	private static final int[] E_TABLE = { 
			31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,
			 7,  8,  9, 10,  1, 12, 11, 12, 13, 14, 15, 16,
			15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 
			23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0
			};
	//S-box表
	private static final int S_BOX[][][] = { 
			{ 
				{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
				{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
				{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
				{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
			},
			{ 
				{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
				{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
				{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
				{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } 
			},
			{ 
				{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
				{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
				{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
				{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } 
			},
			{ 
				{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
				{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
				{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
				{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
			},
			{ 
				{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
				{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
				{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
				{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } 
			},
			{ 
				{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
				{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
				{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
				{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } 
			},
			{ 
				{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
				{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
				{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
				{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } 
			},
			{ 
				{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
				{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
				{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
				{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } 
			} 
		};
	//P盒置换表
	private static final int[] P_BOX = {
			   15,  6, 19, 20,                                                                //P-change
	           28, 11, 27, 16,
	            0, 14, 22, 25,
	            4, 17, 30,  9,
	            1,  7, 23, 13,
	           31, 26,  2,  8,
	           18, 12, 29,  5,
	           21, 10,  3, 24
	 };

	
	
	// 该DES加密的秘钥
	private DESKey key;

	/**
	 * 添加秘钥
	 * 
	 * @param key
	 */
	public DES(DESKey key) {
		this.key = key;
	}
	
	/*
	 * 加密一个分组,数组的每一个元素代表一位
	 */
	public byte[] encryptBlock(byte[] plainBit) {
		byte[] leftBit = getLeftBit(plainBit);
		byte[] rightBit = getRightBit(plainBit);

		for (int i = 0; i < 16; i++) {
			byte[] lTemp = leftBit;
			leftBit = rightBit;
			rightBit = xOr(lTemp, F(rightBit, key.getSubKey(i + 1)));
		}

		byte[] cipherBit = merge(leftBit, rightBit);

		return cipherBit;
	}

	/*
	 * 解密一个分组
	 */
	public byte[] decryptBlock(byte[] cipherBit) {
		byte[] leftBit = getLeftBit(cipherBit);
		byte[] rightBit = getRightBit(cipherBit);

		for (int i = 15; i >= 0; i--) {
			byte[] rTemp = rightBit;
			rightBit = leftBit;
			leftBit = xOr(rTemp, F(rightBit, key.getSubKey(i + 1)));
		}

		byte[] plainBit = merge(leftBit, rightBit);

		return plainBit;
	}

	/*
	 * 获取右边32位数据
	 */
	private byte[] getRightBit(byte[] b) {
		byte[] rightBit = new byte[32];
		for (int i = 0; i < 32; i++) {
			rightBit[i] = b[i + 32];
		}
		return rightBit;
	}

	/*
	 * 获取左边的32位数据
	 */
	private byte[] getLeftBit(byte[] b) {
		byte[] leftBit = new byte[32];
		for (int i = 0; i < 32; i++) {
			leftBit[i] = b[i];
		}
		return leftBit;
	}

	/*
	 * 合并左32位和右32位
	 */
	private byte[] merge(byte[] left, byte[] right) {
		byte[] entry = new byte[64];
		for (int i = 0; i < 32; i++) {
			entry[i] = left[i];
		}
		for (int i = 0; i < 32; i++) {
			entry[i + 32] = right[i];
		}
		return entry;
	}

	/*
	 * 异或操作
	 */
	private byte[] xOr(byte[] a, byte[] b) {
		byte[] result = new byte[a.length];

		for (int i = 0; i < a.length; i++) {
			result[i] = (byte) (a[i] ^ b[i]);
		}
		return result;
	}

	/*
	 * Fiestel运算函数
	 */
	private byte[] F(byte[] text, byte[] key) {
		//扩展
		byte[] ext = expand(text);
		//与秘钥异或
		byte[] or = xOr(ext, key);
		//S盒压缩处理
		byte[] sbox = sBox(or);
		//P盒置换
		byte[] p = pBox(sbox);

		return p;
	}

	/*
	 * 扩展:将32位的序列扩展为48位的序列。
	 */
	private byte[] expand(byte[] bytes) {
		byte[] ext = new byte[48];
		for (int i = 0; i < E_TABLE.length; i++) {
			ext[i] = bytes[E_TABLE[i]];
		}
		return ext;
	}

	/*
	 * sBox压缩处理：将每6位二进制根据S_BOX映射为4位二进制
	 * 输入：48位二进制
	 * 输出：32位二进制
	 */
	private byte[] sBox(byte[] input) {
		byte[] output = new byte[32];
		for (int i = 0; i < 48; i+=6) {
			//第n组数（0-7）
			int n = i / 6;
			//行
			int row = input[i + 0] + input[i + 5];
			//列
			int col = input[i + 1] + input[i + 2] + input[i + 3] + input[i + 4];
			//盒子里面的值
			int value = S_BOX[n][row][col];
			output[n*4 + 3] = (byte) (value >> 0 & 0x1);
			output[n*4 + 2] = (byte) (value >> 1 & 0x1);
			output[n*4 + 1] = (byte) (value >> 2 & 0x1);
			output[n*4 + 0] = (byte) (value >> 3 & 0x1); 
		}
		
		return output;
	}
	
	/*
	 * P盒置换
	 */
	private byte[] pBox(byte[] input) {
		byte[] output = new byte[32];
		
		for (int i = 0; i < 32; i++) {
			output[i] = input[P_BOX[i]];
		}
		return output;
	}
	
	public static void main(String[] args) {
		//生成key
		DESKey key = new DESKey(randomBytes(56));
		//加密器
		DES des = new DES(key);
		//生成随机数据
		byte[] plaintext = randomBytes(64);
		//加密数据
		byte[] ciphertext = des.encryptBlock(plaintext);
		//解密数据
		byte[] afterDecryptText = des.decryptBlock(ciphertext);
		
		System.out.println("原始数据：");
		printData(plaintext);
		System.out.println("加密后的数据：");
		printData(ciphertext);
		System.out.println("解密后的数据：");
		printData(afterDecryptText);
		System.out.println("加密密钥：");
		printData(key.getOriginKey());
	}

	/*
	 * 单元测试
	 */
	public static byte[] randomBytes(int num) {
		Random random = new Random();
		byte[] keys = new byte[num];
		for (int i = 0; i < num; i++) {
			keys[i] = (byte) random.nextInt(2);
		}
		return keys;
	}
	
	private static void printData(byte[] data) {
		for (int i = 0; i < data.length; i++) {
			System.out.print(data[i]);
		}
		System.out.println();
	}

}
