package com.fulong.security.elgamal;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 非对称加密算法ElGamal
 * 
 * 说明：对于：“Illegal key size or default parameters”异常，
 * 是因为美国的出口限制，Sun通过权限文件（local_policy.jar、US_export_policy.jar）
 * 做了相应限制。因此存在一些问题.
 * 
 * @Author:zhuyy
 * @Date:2016年12月31日
 */
public class MyElGamal {
	public static void bcElGamal(String src){
		try {
			//公钥加密、私钥解密
			Security.addProvider(new BouncyCastleProvider());
			
			//1.初始化密钥
			AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
			algorithmParameterGenerator.init(256);
			AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
			DHParameterSpec dhParameterSpec = algorithmParameters.getParameterSpec(DHParameterSpec.class);
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
			keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey elGamalPublicKey = keyPair.getPublic();
			PrivateKey elGamalPrivateKey = keyPair.getPrivate();
			System.out.println("Public Key: " + Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
			System.out.println("Private Key: " + Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));
			
			/** 以下会出现Illegal key size or default parameters异常 */
			
			//2.公钥加密、私钥解密--加密
			/*X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("公钥加密、私钥解密--加密: " + Base64.encodeBase64String(result));*/
			
			//3.公钥加密、私钥解密--解密
			/*PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
			keyFactory = KeyFactory.getInstance("ElGamal");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			result = cipher.doFinal(result);
			System.out.println("公钥加密、私钥解密--解密: " + new String(result));*/
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
