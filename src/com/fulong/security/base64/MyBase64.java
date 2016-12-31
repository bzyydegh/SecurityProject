package com.fulong.security.base64;

import java.io.IOException;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * 实现Base64算法
 * Jdk/Commonc Codec/Bouncy Castle
 * @Author:zhuyy
 * @Date:2016年12月30日
 */
public class MyBase64 {

	public static void jdkBase64(String src){
		try {
			BASE64Encoder encoder = new BASE64Encoder();
			String encode = encoder.encode(src.getBytes());
			System.out.println("jdkBase64加密后: " + encode);
			
			BASE64Decoder decoder = new BASE64Decoder();
			System.out.println("jdkBase64解密后: " + 
					new String(decoder.decodeBuffer(encode)));
		} catch (IOException e) {
			System.out.println("jdkBase64解密失败...");
			e.printStackTrace();
		}
	}
	
	public static void commonsCodecBase64(String src){
		byte[] encodeBytes = Base64.
				encodeBase64(src.getBytes()); //org.apache.commons
		System.out.println("commonsCodecBase64加密后: " + 
				new String(encodeBytes));
		
		byte[] decodeBytes = Base64.decodeBase64(encodeBytes);
		System.out.println("commonsCodecBase64解密后: " + 
				new String(decodeBytes));
	}
	
	public static void bouncyCastleBase64(String src){
		byte[] encodeBytes = org.bouncycastle.util.encoders.
				Base64.encode(src.getBytes());
		System.out.println("bouncyCastleBase64加密后: " + 
				new String(encodeBytes));
		
		byte[] decodeBytes = org.bouncycastle.util.encoders.
				Base64.decode(encodeBytes);
		System.out.println("bouncyCastleBase64解密后: " + 
				new String(decodeBytes));
	}
}
