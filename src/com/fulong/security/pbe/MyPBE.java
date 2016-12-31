package com.fulong.security.pbe;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.apache.commons.codec.binary.Base64;

/**
 * 对称加密算法PBE
 * @Author:zhuyy
 * @Date:2016年12月31日
 */
public class MyPBE {
	public static void jdkPBE(String src){
		try {
			//初始化盐
			SecureRandom secureRandom = new SecureRandom();
			byte[] salt = secureRandom.generateSeed(8);
			
			//口令与密钥
			String pwd = "fulongzyy";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(pwd.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
			Key key = factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec  parameterSpec = new PBEParameterSpec(salt, 100);
			Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
			cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk-PBE加密: " + Base64.encodeBase64String(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
			result = cipher.doFinal(result);
			System.out.println("jdk-PBE解密: " + new String(result));
		} catch (Exception e) {
			System.out.println("jdk-PBE加密失败...");
			e.printStackTrace();
		}
	}
}
