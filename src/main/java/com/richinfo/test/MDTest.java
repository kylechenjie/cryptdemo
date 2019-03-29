package com.richinfo.test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;

/**
 * 消息摘要测试
 *
 */
public class MDTest {

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
	
	public static byte[] MessageDigest(String content,String type) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance(type);
			return md.digest(content.getBytes());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] SHA3(String content,int size){
		byte[] bytes = content.getBytes();
		Digest digest = new SHA3Digest(size);
		digest.update(bytes, 0, bytes.length);
		byte[] rsData = new byte[digest.getDigestSize()];
		digest.doFinal(rsData, 0);
		return rsData;
	}
	
	
	public static void main(String[] args) {
		String content = "君不见黄河之水天上来";
		System.out.println(Byte2String(MessageDigest(content,"MD5")));
		System.out.println(Byte2String(MessageDigest(content,"SHA-256")));
		System.out.println(Byte2String(MessageDigest(content,"SHA-512")));
		
		System.out.println(Byte2String(SHA3(content,224)));
		System.out.println(Byte2String(SHA3(content,256)));
		System.out.println(Byte2String(SHA3(content,512)));
	}

}
