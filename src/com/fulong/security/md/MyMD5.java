package com.fulong.security.md;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * MD5,MD2,MD4加密
 * JDK/bouncycastle/apache
 * @Author:zhuyy
 * @Date:2016年12月31日
 */
public class MyMD5 {
	public static void jdkMD5(String src){
		try {
			MessageDigest md = MessageDigest.getInstance("md5");
			byte[] md5Bytes = md.digest(src.getBytes());
			System.out.println("jdkMD5-1: " + 
					Hex.encodeHexString(md5Bytes));
			//将字节数组转换为字符串
			StringBuffer strBuf = new StringBuffer();
			for(int i = 0; i < md5Bytes.length; i++) {
				if(Integer.toHexString(0xff & md5Bytes[i]).length() == 1){
					strBuf.append("0").append(Integer.toHexString(0xff &
							md5Bytes[i]));
				}else{
					strBuf.append(Integer.toHexString(0xff & md5Bytes[i]));
				}
			}
			System.out.println("jdkMD5-2: " + strBuf.toString());
		} catch (NoSuchAlgorithmException e) {
			System.out.println("jdkMD5加密失败...");
			e.printStackTrace();
		}
	}
	
	public static void jdkMD2(String src){
		try {
			MessageDigest md = MessageDigest.getInstance("md2");
			byte[] md2Bytes = md.digest(src.getBytes());
			System.out.println("jdkMD2加密后: " + 
					Hex.encodeHexString(md2Bytes)); //将字节数组转换为字符串
		} catch (NoSuchAlgorithmException e) {
			System.out.println("jdkMD2加密失败...");
			e.printStackTrace();
		}
	}
	
	public static void bcMD4(String src){
		Digest digest = new MD4Digest();
		digest.update(src.getBytes(), 0, src.getBytes().length);
		byte[] md4Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md4Bytes, 0);
		System.out.println("bcMD4加密后: " + 
				org.bouncycastle.util.encoders.
					Hex.toHexString(md4Bytes));
	}
	
	public static void bcJdkMD4(String src){
		Security.addProvider(new BouncyCastleProvider()); //给JDK动态添加Provider
		try {
			MessageDigest md = MessageDigest.getInstance("MD4");
			byte[] md4Bytes = md.digest(src.getBytes());
			System.out.println("bcJdkMD4加密后: " + 
						org.bouncycastle.util.encoders.
							Hex.toHexString(md4Bytes));
		} catch (NoSuchAlgorithmException e) {
			System.out.println("bcJdkMD4加密失败...");
			e.printStackTrace();
		}
	}
	
	public static void bcMD5(String src){
		Digest digest = new MD5Digest();
		digest.update(src.getBytes(), 0, src.getBytes().length);
		byte[] md5Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md5Bytes, 0);
		System.out.println("bcMD5加密后: " + 
				org.bouncycastle.util.encoders.
					Hex.toHexString(md5Bytes));
	}
	
	public static void bcMD2(String src){
		Digest digest = new MD2Digest();
		digest.update(src.getBytes(), 0, src.getBytes().length);
		byte[] md2Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md2Bytes, 0);
		System.out.println("bcMD2加密后: " + 
				org.bouncycastle.util.encoders.
					Hex.toHexString(md2Bytes));
	}
	
	public static void ccMD5(String src){
		System.out.println("ccMD5加密后: " + 
				DigestUtils.md5Hex(src.getBytes()));
	}
	
	public static void ccMD2(String src){
		System.out.println("ccMD2加密后: " + 
				DigestUtils.md2Hex(src.getBytes()));
	}
}
