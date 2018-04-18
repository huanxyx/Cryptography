package main.java.cryptography.aes;

/**
 * @author Huan
 * @date: 2018年4月15日 上午10:36:57	
 * 加密器：
 * 		传入密钥生成器，实现加密，解密操作
 */
public class AES {
	//子秘钥生成器
	private AESKey subKeyGenerator;
	
	/**
	 * 根据密钥生成AES加密器
	 * @param key 子秘钥生成器
	 */
	public AES(AESKey key) {
		this.subKeyGenerator = key;
	}
	
	
	/**
	 * 加密数据
	 * @param data				加密的数据，大小为16的字节数组
	 * @return
	 */
	public byte[] encrypt(byte[] data) {
		//将128位的分组看成4*4的字节数组
		int[][] state = AESUtil.translate1To2(data);
		
		//初始异或
		state = addRoundKey(state, 0);
		//前9轮处理
		for (int i = 1; i < 10; i++) {
			state = subByte(state);
			state = shiftRow(state);
			state = mixColumns(state);
			state = addRoundKey(state, i);
		}
		//最后一轮处理
		state = subByte(state);
		state = shiftRow(state);
		state = addRoundKey(state, 10);
		
		//将4*4字节数组转换为16字节数组
		byte[] result = AESUtil.translate2To1(state);
		
		return result;
	}
	
	/**
	 * 解密数据
	 * @param data				解密的数据，大小为16的字节数组
	 * @return
	 */
	public byte[] decrypt(byte[] data) {
		int[][] state = AESUtil.translate1To2(data);
		
		state = addRoundKey(state, 10);

		for (int i = 9; i >= 1; i--) {
			state = inShiftRow(state);
			state = inSubByte(state);
			state = addRoundKey(state, i);
			state = inMixColumns(state);
			
		}
		state = inShiftRow(state);
		state = inSubByte(state);
		state = addRoundKey(state, 0);
		
		
		byte[] result = AESUtil.translate2To1(state);
		
		return result;
	}
	
	
	//字节替换
	private static int[][] subByte(int[][] data) {
		int[][] state = new int[4][4];
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = AESUtil.replaceByteBySBox( AESUtil.S_BOX, data[i][j]);
			}
		}
		
		return state;
	}
	
	//行位移
	private static int[][] shiftRow(int[][] data) {
		int[][] state = new int[4][];
		
		for (int i = 0; i < 4; i++) {
			state[i] = AESUtil.loopLeftMove(data[i], i);
		}
		
		return state;
	}
	
	//列混合
	private static int[][] mixColumns(int[][] data) {
		int[][] state = new int[4][4];
		
		for (int col = 0; col < 4; col++) {					//列
			for (int row = 0; row < 4; row++) {				//行
				state[row][col] = AESUtil.matrixCal(AESUtil.MIX_COL, data, row, col);
			}
		}
		
		return state;
	}
	
	//轮密钥加
	private int[][] addRoundKey(int[][] data, int round) {
		int[][] state = new int[4][4];
		int[][] subKey = subKeyGenerator.getSubKey(round);
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = data[i][j] ^ subKey[i][j];
			}
		}
		
		return state;
	}
	
	
	//字节替换(逆)
	private static int[][] inSubByte(int[][] data) {
		int[][] state = new int[4][4];
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = AESUtil.replaceByteBySBox( AESUtil.IN_S_BOX, data[i][j]);
			}
		}
		
		return state;
	}
	
	//行位移(逆)
	private static int[][] inShiftRow(int[][] data) {
		int[][] state = new int[4][];
		
		for (int i = 0; i < 4; i++) {
			state[i] = AESUtil.loopLeftMove(data[i], -i);
		}
		
		return state;
	}
	
	//列混合(逆)
	private static int[][] inMixColumns(int[][] data) {
		int[][] state = new int[4][4];
		
		
		for (int col = 0; col < 4; col++) {					//列
			for (int row = 0; row < 4; row++) {				//行
				state[row][col] = AESUtil.matrixCal(AESUtil.IN_MIX_COL, data, row, col);
			}
		}
		
		return state;
	}
	
	public static void main(String[] args) {
		byte[] b = new byte[] {0x63, 0x53, (byte) 0xe0, (byte) 0x8c, 0x09, 0x60, (byte) 0xe1, 0x04, (byte) 0xcd, 0x70, 
				(byte) 0xb7, 0x51, (byte) 0xba, (byte) 0xca, (byte) 0xd0, (byte) 0xe7};
		int[][] matrix = AESUtil.translate1To2(b);
//		int[][] matrix = new int[][] {
//			{0xC9,0xE5,0xFD,0x2B},
//			{0x7A,0xF2,0x78,0x6E},
//			{0x63,0x9C,0x26,0x67},
//			{0xB0,0xA7,0x82,0xE5}
//		};
		
//		int[][] matrix = new int[][] {
//			{0xD4, 0xE7, 0xCD, 0x66},
//			{0x28, 0x02, 0xE5, 0xBB},
//			{0xBE, 0xC6, 0xD6, 0xBF},
//			{0x22, 0x0F, 0xDF, 0xA5}
//		};
		
		int[][] MixColumns = mixColumns(matrix);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++)
				System.out.print(Integer.toHexString(0xff & MixColumns[i][j]) + " ");
			System.out.println();
		}
		int[][] inMixColumns = inMixColumns(MixColumns);
		
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++)
				System.out.print(Integer.toHexString(0xff & inMixColumns[i][j]) + " ");
			System.out.println();
		}
		
	}
}
