package main.java.cryptography.des;

import java.util.Random;

/**
 * Des加密的秘钥
 * getSubKey(n)根据n获取当前趟加密的子秘钥
 * @author Huan
 *
 */
public class DESKey {
	private static final int[] LK = new int[] {
	    49, 42, 35, 28, 21, 14,  7,  
	     0, 50, 43, 36, 29, 22, 15,  
	     8,  1, 51, 44, 37, 30, 23,  
	    16,  9,  2, 52, 45, 38, 31  
	};
	private static final int[] RK = new int[] {
		55, 48, 41, 34, 27, 20, 13,  
		 6, 54, 47, 40, 33, 26, 19,  
		12,  5, 53, 46, 39, 32, 25,  
		18, 11,  4, 24, 17, 10,  3  	
	};
	// 缺少8,17,21,24
	private static final int[] LP = new int[] {
		13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,  
		22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1  
	};
	// 缺少6,9,14,25
	private static final int[] RP = new int[] {
		12, 23,  2,  8, 18, 26,  1, 11, 22, 16,  4, 19,  
		15, 20, 10, 27,  5, 24, 17, 13, 21,  7,  0,  3  	
	};
	
	private final byte[] originKey;					// 原始秘钥
	private byte[] currentKey;						// 当前秘钥(56位)
	private byte[][] allSubKey = new byte[17][];	// 存储着每轮计算的子秘钥
	
	/**
	 *  得到原始秘钥(56位)
	 * @param originKey
	 */
	public DESKey(byte[] originKey) {
		this.originKey = new byte[originKey.length];
		
		for(int i = 0; i < originKey.length; i++) {
			this.originKey[i] = originKey[i];
		}

		this.currentKey = this.originKey;
	}
	
	/**
	 * 获取原始密钥
	 * @return
	 */
	public byte[] getOriginKey() {
		return originKey.clone();
	}
	
	/**
	 *  获取当前循环的子秘钥
	 * @param r				当前循环数(1..16)
	 * @return
	 */
	public byte[] getSubKey(int r) {
		// 使用之前得到的子秘钥
		if(allSubKey[r] != null)
			return allSubKey[r];
		
		// 获取leftChildKey和rightChildKey(28位)
		byte[] leftSubKey = leftKeyMapping(currentKey);
		byte[] rightSubKey = rightKeyMapping(currentKey);
		
		// 位移操作
		if(r == 1 || r == 2 || r == 9 || r == 16) {
			// 循环左移一位
			leftSubKey = moveOneLeft(leftSubKey);
			rightSubKey = moveOneLeft(rightSubKey);
		} else {
			// 循环左移两位
			leftSubKey = moveTwoLeft(leftSubKey);
			rightSubKey = moveTwoLeft(rightSubKey);
		}
		
		// 设置下一次使用的秘钥（位）
		this.currentKey = merge(leftSubKey, rightSubKey);
		
		
		// P置换（将28位秘钥转换为24位）
		leftSubKey = replaceLeftKey(leftSubKey);
		rightSubKey = replaceRightKey(rightSubKey);
		
		
		// 合并获取当前的子秘钥
		byte[] subKey = merge(leftSubKey, rightSubKey);
		
		// 保存当前轮的子秘钥，以便下次方便调用
		allSubKey[r] = subKey;
		return subKey;
	}
	
	// 获取当前秘钥的LeftKey
	private byte[] leftKeyMapping(byte[] arr) {
		return keyMapping(arr, LK);
	}
	// 获取当前秘钥的RightKey
	private byte[] rightKeyMapping(byte[] arr) {
		return keyMapping(arr, RK);
	}
	
	private byte[] keyMapping(byte[] arr, int[] table) {
		byte[] result = new byte[table.length];
		for(int i = 0; i < table.length; i++) {
			result[i] = arr[table[i]];
		}
		return result;
	}
	
	// 循环左移一位
	private byte[] moveOneLeft(byte[] arr) {
		byte last = arr[0];
		for(int i = 0; i < arr.length-1; i++) {
			arr[i] = arr[i+1];
		}
		arr[arr.length-1] = last;
		return arr;
	}
	// 循环左移两位
	private byte[] moveTwoLeft(byte[] arr) {
		byte last1 = arr[1];
		byte last2 = arr[0];
		for(int i = 0; i < arr.length-2; i++) {
			arr[i] = arr[i+2];
		}
		arr[arr.length-1] = last1;
		arr[arr.length-2] = last2;
		return arr;
	}
	
	// 合并左右两个部分
	private byte[] merge(byte[] leftKey, byte[] rightKey) {
		byte[] result = new byte[leftKey.length*2];	
		for(int i = 0; i < leftKey.length; i++) {
			result[i] = leftKey[i];
		}
		for(int i = 0; i < rightKey.length; i++) {
			result[i + leftKey.length] = rightKey[i];
		}
		
		return result;
	}
	
	// 置换左边
	private byte[] replaceLeftKey(byte[] arr) {
		return replaceKey(arr, LP);
	}
	// 置换右边
	private byte[] replaceRightKey(byte[] arr) {
		return replaceKey(arr, RP);
	}
	// 置换
	private byte[] replaceKey(byte[] arr, int[] table) {
		byte[] result = new byte[table.length];
		for(int i = 0; i < table.length; i++) {
			result[i] = arr[table[i]];
		}
		return result;
	}
	
	

	/*
	 * 单元测试
	 */
	public static void main(String[] args) {
		byte[] key = randomBytes(56);
		printData(key);
		DESKey k = new DESKey(key);
		k.getSubKey(1);
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