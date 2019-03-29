package com.richinfo.test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACTest {

	private static String Byte2String(byte[] b) {
        StringBuilder hs = new StringBuilder();
        int n = 0;
        while (b != null && n < b.length) {
            String stmp = Integer.toHexString(b[n] & 255);
            if (stmp.length() == 1) {
                hs.append('0');
            }
            hs.append(stmp);
            n++;
        }
        return hs.toString().toUpperCase(Locale.CHINA);
    }
	
	public static byte[] Digest(String content,String key,String type) {
		try {
			 Mac hmac = Mac.getInstance(type);
			 SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), type);
			 hmac.init(secret_key);
			 byte[] array = hmac.doFinal(content.getBytes("UTF-8"));
			 return array;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	public static void main(String[] args) {
		String content = "君不见黄河之水天上来";
		String key = "hehe";
		System.out.println(Byte2String(Digest(content,key,"HmacMD5")));
		System.out.println(Byte2String(Digest(content,key,"HmacSHA1")));
		System.out.println(Byte2String(Digest(content,key,"HmacSHA256")));
	}

}
