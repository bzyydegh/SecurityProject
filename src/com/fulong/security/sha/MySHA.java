package com.fulong.security.sha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * SHA消息摘要算法
 * JDK/BC/CC
 * @Author:zhuyy
 * @Date:2016年12月31日
 */
public class MySHA {
	public static void jdkSHA1(String src){
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(src.getBytes());
			System.out.println("jdkSHA1加密后: " + 
					Hex.encodeHexString(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			System.out.println("jdkSHA1加密失败:");
			e.printStackTrace();
		}
	}
	
	public static void bcSHA1(String src){
		Digest digest = new SHA1Digest();
		digest.update(src.getBytes(), 0, src.getBytes().length);
		byte[] sha1Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(sha1Bytes, 0);
		System.out.println("bcSHA1加密后: " + 
				org.bouncycastle.util.encoders.
					Hex.toHexString(sha1Bytes));
	}
	
	public static void bcSHA224(String src){
		Digest digest = new SHA224Digest();
		digest.update(src.getBytes(), 0, src.getBytes().length);
		byte[] sha224Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(sha224Bytes, 0);
		System.out.println("bcSHA224加密后: " + 
				org.bouncycastle.util.encoders.
					Hex.toHexString(sha224Bytes));
	}
	
	public static void bcSHA224_2(String src){
		Security.addProvider(new BouncyCastleProvider()); //给JDK动态添加Provider
		try {
			MessageDigest md = MessageDigest.getInstance("SHA224");
			byte[] bcSHA224Bytes = md.digest(src.getBytes());
			System.out.println("bcSHA224_2加密后: " + 
					org.bouncycastle.util.encoders.
						Hex.toHexString(bcSHA224Bytes));
		} catch (NoSuchAlgorithmException e) {
			System.out.println("jdkSHA224_2加密失败:");
			e.printStackTrace();
		}
	}
	
	public static void ccSHA1(String src){
		System.out.println("ccSHA1-1: " + 
				DigestUtils.sha1Hex(src.getBytes()));
		System.out.println("ccSHA1-2: " + 
				DigestUtils.sha1Hex(src));
	}
}
