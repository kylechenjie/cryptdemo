package com.richinfo.test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


/**
 * AES测试
 *
 */
public class AESTest {

	public static String AESEncrypt(String content, String sKey) {
		try {
			byte[] encryptedBytes;
			byte[] byteContent = content.getBytes("UTF-8");
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyGenerator keyGenerator=KeyGenerator.getInstance("AES","BC");
			keyGenerator.init(256, new SecureRandom(sKey.getBytes()));
			SecretKey key=keyGenerator.generateKey();
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec("1234567812345678".getBytes());
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			encryptedBytes = cipher.doFinal(byteContent);		
			return Base64.getEncoder().encodeToString(encryptedBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static void main(String[] args) {
		String key = "1234567890123456";
		String content = "君不见黄河之水天上来";
		System.out.println(AESEncrypt(content,key));

	}

}
