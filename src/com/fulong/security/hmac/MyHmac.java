package com.fulong.security.hmac;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * 消息摘要算法MAC
 * @Author:zhuyy
 * @Date:2016年12月31日
 */
public class MyHmac {
	
	public static void jdkHmac(String src){
		try {
			KeyGenerator keyGenerator = KeyGenerator.
					getInstance("HmacMD5"); //初始化KeyGenerator
			SecretKey secretKey = keyGenerator.generateKey(); //产生密钥
			byte[] key = secretKey.getEncoded(); //获得密钥(自己生成)
			//自定义密钥
			/*byte[] key = org.apache.commons.codec.binary.
					Hex.decodeHex(new char[]
							{'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a','a'});*/
			SecretKey restoreSecretKey = new SecretKeySpec(key, "HmacMD5"); //还原密钥
			Mac mac = Mac.getInstance(restoreSecretKey.getAlgorithm()); //实例化MAC
			mac.init(restoreSecretKey); //初始化MAC
			byte[] hmacMD5Bytes = mac.doFinal(src.getBytes()); //执行摘要
			System.out.println("jdk-hmacMD5: " + Hex.toHexString(hmacMD5Bytes));
		} catch (Exception e) {
			System.out.println("jdkHmac加密失败...");
			e.printStackTrace();
		}
	}
	
	public static void bcHmacMD5(String src){
		HMac hMac = new HMac(new MD5Digest());
		hMac.init(new KeyParameter(Hex.decode("aaaaaaaaaa")));
		hMac.update(src.getBytes(), 0, src.getBytes().length);
		
		byte[] hmacMD5Bytes = new byte[hMac.getMacSize()]; //执行摘要
		hMac.doFinal(hmacMD5Bytes, 0);
		System.out.println("bcHmacMD5: " + Hex.toHexString(hmacMD5Bytes));
	}
}
