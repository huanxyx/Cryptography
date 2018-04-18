package main.java.cryptography.aes;

/**
 * @author Huan
 * @date: 2018年4月15日 下午11:32:55
 */
public class AESKey {

	//真实密钥
	private byte[] key;
	//扩展密钥(子秘钥)
	private int[] keyW;
	
	
	/**
	 * 根据密钥创建子秘钥生成器
	 * @param key 密钥（16个字节）
	 */
	public AESKey(byte[] key) {
		this.key = key;
		this.keyW = extendKey(key);
	}
	
	public byte[] getKey() {
		return key;
	}
	
	/**
	 * 获取当前轮的子秘钥
	 * @param round 	当前轮数(0-10轮)
	 * @return 			子秘钥（4*4的字节数组）
	 */
	public int[][] getSubKey(int round) {
		int[] result = new int[4];
		result[0] = keyW[4*round];
		result[1] = keyW[4*round+1];
		result[2] = keyW[4*round+2];
		result[3] = keyW[4*round+3];
		
		return AESUtil.splitIntArr(result);
	}
	
	
	//扩展秘钥(32*4*1 => 32*4*11)
	private static int[] extendKey(byte[] key) {
		int[] keyW = new int[44];
		//生成起始的4个扩展密钥
		for (int i = 0; i < 4; i++) {
			keyW[i] = AESUtil.translate4ByteTo1Int(key, i*4, 4);
		}
		
		//生成其余的扩展秘钥
		for (int i = 4, j = 0; i < 44; i++) {
			if (i % 4 == 0) {
				keyW[i] = keyW[i - 4] ^ T(keyW[i - 1], j);
				j++;
			} else {
				keyW[i] = keyW[i - 4] ^ keyW[i - 1];
			}
		}
		return keyW;
	}
	
	//秘钥扩展中的T函数(从0到9)
	private static int T(int num, int round) {
		//字循环位移（一位）
		int move = AESUtil.loopLeftMove(num, 1);
		//字节替换
		int replace = AESUtil.replaceIntBySBox( AESUtil.S_BOX, move);
		//轮常量异或(非线性替换)
		int xor = replace ^ AESUtil.RCON[round]; 
	
		return xor;
	}
	
	/**
	 * 单元测试
	 * @param args
	 */
	public static void main(String[] args) {
		byte[] aByte = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 
				0x0c, 0x0d, 0x0e, 0x0f };
		AESKey keyGenerator = new AESKey(aByte);
		
		for(int i = 0; i < 11; i++) {
			int[][] key = keyGenerator.getSubKey(i);
			for (int k = 0; k < 4; k++) {
				for (int j = 0; j < 4; j++) {
					System.out.print(Integer.toHexString(key[k][j]) + " ");
				}
				System.out.println();
			}
			System.out.println();
		}
	}
}
