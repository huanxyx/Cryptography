package main.java.cryptography.A51;

import java.util.Arrays;

public class A51 {
	//寄存器X（19位）
	private byte[] mX;
	//寄存器Y（22位）
	private byte[] mY;
	//寄存器Z（23位）
	private byte[] mZ;
	
	public A51(byte[] X, byte[] Y, byte[] Z) {
		if (X.length != 19 || Y.length != 22 || Z.length != 23)
			throw new IllegalArgumentException("数组大小不合法！");
		mX = X;
		mY = Y;
		mZ = Z;
	}
	
	/**
	 * 获取密码流
	 * @return
	 */
	public byte getSecretStream() {
		byte m = maj();
		if (mX[8] == m) operationX();
		if (mY[10] == m) operationY();
		if (mZ[10] == m) operationZ();
		
		return (byte) (mX[18] ^ mY[21] ^ mZ[22]);
	}
	
	/**
	 * 获取X寄存器
	 * @return
	 */
	public byte[] getX() {
		return mX;
	}
	
	/**
	 * 获取Y寄存器
	 * @return
	 */
	public byte[] getY() {
		return mY;
	}
	
	/**
	 * 获取Z寄存器
	 * @return
	 */
	public byte[] getZ() {
		return mZ;
	}
	
	private void operationX() {
		byte t = (byte) (mX[13] ^ mX[16] ^ mX[17] ^ mX[18]);
		for (int i = 18; i >= 1; i--) {
			mX[i] = mX[i-1];
		}
		mX[0] = t;
	}
	
	private void operationY() {
		byte t = (byte) (mY[20] ^ mY[21]);
		for (int i = 21; i >= 1; i--) {
			mY[i] = mY[i-1];
		}
		mY[0] = t;
	} 
	
	private void operationZ() {
		byte t = (byte) (mZ[7] ^ mZ[20] ^ mZ[21] ^ mZ[22]);
		for (int i = 22; i >= 1; i--) {
			mZ[i] = mZ[i-1];
		}
		mZ[0] = t;
	}
	
	private byte maj() {
		return (byte) (mX[8] + mY[10] + mZ[10] >= 2 ? 1 : 0 );
	}
	
	public static void main (String[] args) {
		byte[] X = {1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1};
		byte[] Y = {1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1};
		byte[] Z = {1,1,1,0,0,0,0,1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0};
		
		A51 a51 = new A51(X, Y, Z);
		
		for (int i = 0; i < 32; i++) {
			System.out.print(a51.getSecretStream());
		}
		System.out.println();
		System.out.println(Arrays.toString(a51.getX()));
		System.out.println(Arrays.toString(a51.getY()));
		System.out.println(Arrays.toString(a51.getZ()));
		
	}
}
