package com.fulong.security.test;

import com.fulong.security.aes.MyAES;
import com.fulong.security.base64.MyBase64;
import com.fulong.security.des.My3DES;
import com.fulong.security.des.MyDES;
import com.fulong.security.dh.MyDH;
import com.fulong.security.elgamal.MyElGamal;
import com.fulong.security.hmac.MyHmac;
import com.fulong.security.md.MyMD5;
import com.fulong.security.pbe.MyPBE;
import com.fulong.security.rsa.MyRSA;
import com.fulong.security.sha.MySHA;
import com.fulong.security.sign.SignDSA;
import com.fulong.security.sign.SignECDSA;
import com.fulong.security.sign.SignRSA;

/**
 * 测试
 * @Author:zhuyy
 * @Date:2016年12月30日
 */
public class Test {
	private static String mSrc = "china security base64 md";
	
	public static void main(String[] args) {
		MyBase64.jdkBase64(mSrc);
		MyBase64.commonsCodecBase64(mSrc);
		MyBase64.bouncyCastleBase64(mSrc);
		MyMD5.jdkMD5(mSrc);
		MyMD5.jdkMD2(mSrc);
		MyMD5.bcMD4(mSrc);
		MyMD5.bcJdkMD4(mSrc);
		MyMD5.bcMD5(mSrc);
		MyMD5.bcMD2(mSrc);
		MyMD5.ccMD2(mSrc);
		MyMD5.ccMD5(mSrc);
		MySHA.jdkSHA1(mSrc);
		MySHA.bcSHA1(mSrc);
		MySHA.bcSHA224(mSrc);
		MySHA.bcSHA224_2(mSrc);
		MySHA.ccSHA1(mSrc);
		MyHmac.jdkHmac(mSrc);
		MyHmac.bcHmacMD5(mSrc);
		MyDES.jdkDES(mSrc);
		MyDES.bcDES(mSrc);
		My3DES.jdk3DES(mSrc);
		My3DES.bc3DES(mSrc);
		MyAES.jdkAES(mSrc);
		MyPBE.jdkPBE(mSrc);
		MyDH.jdkDH(mSrc);
		MyRSA.jdkRSA(mSrc);
		MyElGamal.bcElGamal(mSrc);
		SignRSA.jdkRSA(mSrc);
		SignDSA.jdkDSA(mSrc);
		SignECDSA.jdkECDSA(mSrc);
	}
}
