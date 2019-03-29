package com.richinfo.test;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 * DES测试
 *
 */
public class DesTest {
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
	private static byte[] EncryptByKey(byte[] datasource, String key) {
        try{
            SecureRandom random = new SecureRandom();
            
            DESKeySpec desKey = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = keyFactory.generateSecret(desKey);
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, securekey, random);
            return cipher.doFinal(datasource);
        }catch(Throwable e){
            e.printStackTrace();
        }
        return null;
    }
	
	public static void main(String[] args) {
		String data = "君不见黄河之水天上来";
		String key = "12345678";
		byte[] enc = DesTest.EncryptByKey(data.getBytes(), key);
		System.out.println(Byte2String(enc));
		String base64 = Base64.getEncoder().encodeToString(enc);
		System.out.println(base64);

	}

}
