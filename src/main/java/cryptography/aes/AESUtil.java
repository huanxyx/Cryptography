package main.java.cryptography.aes;

import java.util.Arrays;

/**
 * @author Huan
 * @date: 2018年4月15日 下午11:30:56
 * 用于AES相关的函数库：<br/>
 * 		1)转换					<br/>
 * 		2)二进制操作				<br/>
 * 		3)SBOX和轮值表			<br/>
 * 		4)列混合使用表			<br/>
 */
public class AESUtil {
	
	private AESUtil() {
		
	}
	
	//字节替换查找表
	protected static final int S_BOX[][] = {
		    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
		    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, //0
		    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, //1
		    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, //2
		    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, //3
		    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, //4
		    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, //5
		    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, //6
		    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, //7
		    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, //8
		    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, //9
		    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, //A
		    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, //B
		    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, //C
		    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, //D
		    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, //E
		    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}  //F
		};

	
	//字节替换查找表（逆）
	protected static final int IN_S_BOX[][] = {
		    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
		    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
		    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
		    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
		    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
		    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
		    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
		    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
		    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
		    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
		    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
		    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
		    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
		    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
		    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
		    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
		    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} 
		};
	
	//轮值表
	protected static final int[] RCON = {
				0x01000000, 0x02000000,
				0x04000000, 0x08000000,
				0x10000000, 0x20000000,
				0x40000000, 0x80000000,
				0x1b000000, 0x36000000
		}; 
	
	//列混合需要用到的表
	protected static final int[][] MIX_COL = {
			{ 2, 3, 1, 1},
			{ 1, 2, 3, 1},
			{ 1, 1, 2, 3},
			{ 3, 1, 1, 2}
	};
	
	//逆列混合需要用到的表
	protected static final int[][] IN_MIX_COL = {
			{0xe, 0xb, 0xd, 0x9},
			{0x9, 0xe, 0xb, 0xd},
			{0xd, 0x9, 0xe, 0xb},
			{0xb, 0xd, 0x9, 0xe}
	};


	
	//一个字节的大小
	protected static final int BYTE_SIZE = 8;
	
	/**
	 * 根据盒子，置换一个数<br />
	 * 	 	num = 0xf1f2f3f4		<br/>
	 * 		output = 0x(f')(1f')(2f')(3f'4)
	 * @param box			盒子（16*16）
	 * @param num			数（int）
	 * @return				置换后的数（int）
	 */
	protected static int replaceIntBySBox(int[][] box, int num) {
		int temp = 0;
		for (int i = 0; i < 4; i++) {
			int currentByte = getByteByPosition(num, i);
			temp |= replaceByteBySBox(box, currentByte) << (i*BYTE_SIZE);
		}
		return temp;
	}
	
	/**
	 * 通过盒子置换一个字节
	 * @param box	盒子（16*16）
	 * @param b		单个字节
	 * @return		置换后的字节
	 */
	protected static int replaceByteBySBox(int[][] box, int b) {
		int row = (b & 0xf0) >> 4;
		int col = b & 0xf;
		return box[row][col];
	}
	
	/**
	 * 将数往左循环位移指定个数的字节
	 * @param num				指定的数
	 * @param step				循环位移的字节数
	 * @return
	 */
	protected static int loopLeftMove(int num, int step) {
		int temp = 0;
		for (int i = 0; i < 4; i++) {
			int newPos = (i + step + 4) % 4;
			int currentByte = getByteByPosition(num, i);
			temp |= moveByteByPosition( currentByte, newPos);
		}
		return temp;
	}
	
	/*
	 * 将一个字节移动到指定位置生成（0-3）<br/>
	 * 若0xf1f2f3f4,其中<br/>
	 * 			0：f4，<br/>
	 * 			1：f3，<br/>
	 * 			2：f2，<br/>
	 * 			3：f1
	 */
	private static int moveByteByPosition(int num, int pos) {
		int temp = 0;
		temp |= (num & 0xff) << (pos * BYTE_SIZE);
		return temp;
	}
	
	/*
	 * 获取一个整型中指定位置的字节
	 * 若0xf1f2f3f4,其中
	 * 			0：f4，
	 * 			1：f3，
	 * 			2：f2，
	 * 			3：f1
	 */
	private static int getByteByPosition(int num, int pos) {
		int delt = pos * BYTE_SIZE;
		return (num & (0xff << delt)) >>> delt;
	}
	
	/**
	 * 将大小为4的数组往左循环位移
	 * @param rows			数组（Size = 4）
	 * @param step			位移的步数
	 * @return
	 */
	protected static int[] loopLeftMove(int[] rows, int step) {
		int[] rows2 = new int[4];
		for (int j = 0; j < 4; j++) {
			rows2[j] = rows[(step+j+4)%4];
		}
		return rows2;
	}
	

	
	/**
	 * 将4个字节转换为一个int类型(len = 4)<br />
	 * 开头的为高位
	 * @param bytes		字节数组
	 * @param start		开始位置（包括）
	 * @param len		长度
	 * @return			转换后的数
	 */
	protected static int translate4ByteTo1Int(byte[] bytes, int start, int len) {
		int temp = 0;
		for (int i = start, j = 0; j < len; i++, j++) {
			temp |= moveByteByPosition(bytes[i], len - 1 - j);
		}
		return temp;
	}
	
	/**
	 * 将一维数组[16]转换为二维数组[4][4] <br/>
	 * 从列开始转换
	 * @param origin	字节一维数组[16]
	 * @return			二维数组[4][4]
	 */
	protected static int[][] translate1To2(byte[] origin) {
		int[][] temp = new int[4][4];
		
		for (int i = 0; i < 16; i++) {
			int row = i % 4;
			int col = i / 4;
			temp[row][col] = origin[i];
		}
		return temp;
	}
	
	/**
	 * 将二维数组[4][4]转换为一维数组[16] <br/>
	 * 从列开始转换
	 * @param origin 	二维数组[4][4]
	 * @return 			字节一维数组[16]
	 */
	protected static byte[] translate2To1(int[][] origin) {
		byte[] temp = new byte[16];
		
		for (int i = 0; i < 16; i++) {
			int row = i % 4;
			int col = i / 4;
			temp[i] = (byte) origin[row][col];
		}
		return temp;
	}
	
	
	/**
	 * 分割大小为4的整型数组为4*4的字节数组 <br />
	 * 每个数据分割成一列
	 * @param data				输入的大小为4的整数数组
	 * @return					4*4的字节数组
	 */
	protected static int[][] splitIntArr(int[] data) {
		int[][] data2 = new int[4][4];
		
		for (int col = 0; col < 4; col++) {
			for (int row = 0; row < 4; row++) {
				data2[row][col] = getByteByPosition(data[col],3 - row); 
			}
		}
		return data2;
	}
	
	/**
	 * 获取两个矩阵相乘后指定位置的值（基于GF(2^8)域上的运算）
	 * @param mixCol			第一个矩阵(4*4)
	 * @param data				第二个矩阵(4*4)
	 * @param col				新矩阵列坐标(0-3)
	 * @param row				新矩阵行坐标(0-3)
	 * @return					新矩阵指定位置的值
	 */
	protected static int matrixCal(int[][] mixCol, int[][] data, int row, int col) {
		int result = 0;
		for (int i = 0; i < 4; i++) {
			result ^= gfMul(mixCol[row][i], data[i][col]);
		}
		return result;
	}
	

	/*
	 * 多项式GF(2^8)上的乘法运算
	 */
	private static int gfMul(int a, int b) {
		if (a == 0x1) 
			return b;
		else if (a == 0x2)
			return gfMul2(b);
		else if (a == 0x3) 
			return gfMul3(b);
		else if (a == 0x9) 
			return gfMul9(b);
		else if (a == 0xb)		//11
			return gfMul11(b);
		else if (a == 0xd) 		//13
			return gfMul13(b);
		else if (a == 0xe)		//14
			return gfMul14(b);
		
		return 0;
	}
	
	//求解在GF(2^8)上与10的乘法运算(10)，可以直接运算得到。
	private static int gfMul2(int a) {
		int result = (a & 0xff) << 1;
		int a7 = a & 0x80;					//数a中的第七位数
		if (a7 != 0) {						//第七位不为0的情况
			result = (result & 0xff) ^ 0x1b;
		}
		return result & 0xff;
	}
	
	//与11的乘法运算（10 ^ 1）
	private static int gfMul3(int a) {
		return gfMul2(a) ^ a;
	}
	
	//与100的乘法运算(10 * 10)
	private static int gfMul4(int a) {
		return gfMul2(gfMul2(a));
	}
	
	//与1000的乘法运算(100 * 10)
	private static int gfMul8(int a) {
		return gfMul2(gfMul4(a));
	}
	
	//与1001的乘法运算(1000 ^ 1)
	private static int gfMul9(int a) {
		return gfMul8(a) ^ a;
	}
	
	//与1011的乘法运算(1001 ^ 10)
	private static int gfMul11(int a) {
		return gfMul9(a) ^ gfMul2(a);
	}
	
	//与1100的乘法运算(1000 ^ 100)
	private static int gfMul12(int a) {
		return gfMul8(a) ^ gfMul4(a);
	}
	
	//与1101的乘法运算(1100 ^ 1)
	private static int gfMul13(int a) {
		return gfMul12(a) ^ a;
	}
	
	//与1110的乘法运算(1100 ^ 10)
	private static int gfMul14(int a) {
		return gfMul12(a) ^ gfMul2(a);
	}
	
	/**
	 * 单元测试
	 * @param args
	 */
	public static void main(String[] args) {
		int i = 0xf1f0f3f4;
		int i1 = getByteByPosition(i, 0);
		int i2 = getByteByPosition(i, 1);
		int i3 = getByteByPosition(i, 2);
		int i4 = getByteByPosition(i, 3);
		print(i);
		print(i1);
		print(i2);
		print(i3);
		print(i4);
		//测试完getByteByPosition
		int l1 = moveByteByPosition(0xf1, 0);
		int l2 = moveByteByPosition(0xff, 1);
		int l3 = moveByteByPosition(0xff, 2);
		int l4 = moveByteByPosition(0xff, 3);
		print(l1);
		print(l2);
		print(l3);
		print(l4);
		//测试完moveByteByPosition
		
		int m1 = loopLeftMove(i, 0);
		int m2 = loopLeftMove(i, 1);
		int m3 = loopLeftMove(i, 2);
		int m4 = loopLeftMove(i, 3);
		int m5 = loopLeftMove(i, 4);
		print(m1);
		print(m2);
		print(m3);
		print(m4);
		print(m5);
		//测试完loopLeftMove
		byte[] aByte = new byte[]{(byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4};
		int resultInt = translate4ByteTo1Int(aByte, 0, 4);
		print(aByte);
		print(resultInt);
		//测试完translate4ByteTo1Int
		int[] iarr = new int[] {1,2,3,4};
		System.out.println(Arrays.toString(loopLeftMove(iarr, 0)));
		System.out.println(Arrays.toString(loopLeftMove(iarr, 1)));
		System.out.println(Arrays.toString(loopLeftMove(iarr, 2)));
		System.out.println(Arrays.toString(loopLeftMove(iarr, 3)));
		
		for (i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				System.out.print(Integer.toHexString(matrixCal(IN_MIX_COL, MIX_COL, i, j))+ " ");
			}
			System.out.println();
		}
	}
	
	
	public static void print(byte[] aByte) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < aByte.length; i++) {
			builder.append(Integer.toHexString(0xff & aByte[i]) + ",");
		}
		System.out.println(builder.toString());
	}
	public static void print(int[] aByte) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < aByte.length; i++) {
			builder.append(Integer.toHexString(aByte[i]) + ",");
		}
		System.out.println(builder.toString());
	}
	public static void print(int i) {
		System.out.println(Integer.toHexString(i));
	}
}
