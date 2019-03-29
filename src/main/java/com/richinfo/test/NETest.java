package com.richinfo.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.richinfo.test.utils.MyHostnameVerifier;
import com.richinfo.test.utils.MyX509TrustManager;

/**
 * 网易云音乐评论获取测试
 */
public class NETest {
	private final Logger logger = LoggerFactory.getLogger(NETest.class);
	
	public String sKey = "0CoJUm6Qyw8W8jud";
	public String randomKey = "FFFFFFFFFFFFFFFF";

	
	public String post(String songId,String addr,String msg) {
		HttpsURLConnection httpsURLConnection = null;
        InputStream in = null;
        String result = null;
        logger.info("post to addr:{}",addr);
        try {
        	URL url = new URL(addr);
        	SSLContext scContext = SSLContext.getInstance("TLS");
        	scContext.init(null, new TrustManager[]{new MyX509TrustManager()}, new SecureRandom());
        	HttpsURLConnection.setDefaultSSLSocketFactory(scContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(new MyHostnameVerifier());
            
            httpsURLConnection = (HttpsURLConnection) url.openConnection();
            httpsURLConnection.setDoOutput(true);
            httpsURLConnection.setDoInput(true);
            httpsURLConnection.setUseCaches(false);
            httpsURLConnection.setRequestMethod("POST");
            httpsURLConnection.setConnectTimeout(10000);
            httpsURLConnection.setReadTimeout(10000);
            httpsURLConnection.setRequestProperty("Accept", "*/*");
            httpsURLConnection.setRequestProperty("Accept-Encoding", "gzip, deflate, br");
            httpsURLConnection.setRequestProperty("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7");
            httpsURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            httpsURLConnection.setRequestProperty("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36");
            httpsURLConnection.setRequestProperty("Origin", "https://music.163.com");
            httpsURLConnection.setRequestProperty("Referer", "https://music.163.com/song?id="+songId);
            
            
            OutputStream outputStream = httpsURLConnection.getOutputStream();
            byte[] msgBytes = msg.getBytes();
            outputStream.write(msgBytes);

            outputStream.flush();
            outputStream.close();
            
            int responseCode = httpsURLConnection.getResponseCode();
            logger.info("response code: {}" , responseCode);
            if (200 == responseCode) {
            	String encoding = httpsURLConnection.getContentEncoding();
                in = httpsURLConnection.getInputStream();
                
                
                if(encoding == null) {
                	encoding = "unknown";
                }else if(encoding.equals("gzip")) {
        			GZIPInputStream gZIPInputStream = null;
        			gZIPInputStream = new GZIPInputStream(in);
        			
        			BufferedReader bin = new BufferedReader(new InputStreamReader(gZIPInputStream));
        			StringBuffer sb = new StringBuffer();
        			String line = null;
        			while ((line = bin.readLine()) != null) {
        				sb.append(line);
        			}
        			result =sb.toString();
        			bin.close();
        			logger.info("gzip response:\r\n {}",result);
        			
        		}else {
        			BufferedReader bin = new BufferedReader(new InputStreamReader(in));
        			StringBuffer sb = new StringBuffer();
        			String line = null;
        			while ((line = bin.readLine()) != null) {
        				sb.append(line);
        			}
        			result = sb.toString();
        			bin.close();
        			logger.info("response:\r\n {}",result);
        		}
        		
               
                
            } else {
            	logger.error("failed,responseCode:{}",responseCode);
            }
            in.close();
            httpsURLConnection.disconnect();
        } catch (Exception e2) {
        	logger.error("post",e2);
        	logger.error("post error!\n {}" + e2.toString());
            if (in != null) {
                try {
                    in.close();
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
            }
            if (httpsURLConnection != null) {
                httpsURLConnection.disconnect();
            }
        }
        return result;
	}
	
	

	/**
	 * @param songId     歌曲ID
	 * @param paging     是否第一页 true 第一页 其余传入false
	 * @param nowPageNum 当前页数
	 * @return
	 */
	public static String makeContent(String songId, String paging, int nowPageNum) {
		int offset;
		if (nowPageNum < 1) {
			offset = 20;
		}
		offset = (nowPageNum - 1) * 20;
		String baseContent = "{rid:\"R_SO_4_%s\",offset:\"%d\",total:\"%s\",limit:\"20\",csrf_token:\"\"}";
		return String.format(baseContent, songId, offset, paging);
	}

	public Map<String, String> makePostParam(String content) {
		Map<String, String> map = new HashMap<String, String>();
		
		randomKey = RandomStringUtils.random(16, "ABCDEF0123456789");
		//randomKey = "L0dMFl4CY22IpTYn";
		System.out.println("randomKey:"+randomKey);
		String encSecKey = getSecKeyOriginal(randomKey);
		System.out.println("encSecKey:"+encSecKey);

		map.put("params", AESEncrypt((AESEncrypt(content, sKey)), randomKey));
		//map.put("encSecKey", "257348aecb5e556c066de214e531faadd1c55d814f9be95fd06d6bff9f4c7a41f831f6394d5a3fd2e3881736d94a02ca919d952872e7d0a50ebfa1769a7a62d512f5f1ca21aec60bc3819a9c3ffca5eca9a0dba6d6f7249b06f5965ecfff3695b54e1c28f3f624750ed39e7de08fc8493242e26dbc4484a01c76f739e135637c");
		map.put("encSecKey", encSecKey);
		return map;
	}

	public Map<String, String> makePostParam(String songId, String paging, int nowPageNum) {
		String postContent = makeContent(songId, paging, nowPageNum);
		System.out.println("postContent:"+postContent);
		return makePostParam(postContent);
	}	

	public static String AESEncrypt(String content, String sKey) {
		try {
			byte[] encryptedBytes;
			byte[] byteContent = content.getBytes("UTF-8");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(sKey.getBytes(), "AES");
			IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
			encryptedBytes = cipher.doFinal(byteContent);
			String encData = new String(java.util.Base64.getUrlEncoder().encode(encryptedBytes),"utf-8");
			//String encData = URLEncoder.encode(new String(Base64.encode(encryptedBytes),"utf-8"),"utf-8");
			return encData;
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
	
	private String byte2String(byte[] b) {
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
	
	private String format(String result, int n) {
        if (result.length() >= n) {
            result = result.substring(result.length() - n, result.length());
        } else {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = n; i > result.length(); i--) {
                stringBuilder.append("0");
            }
            stringBuilder.append(result);
            result = stringBuilder.toString();
        }
        return result;
    }
	//RSA加密方法一
	public String getSecKey(String data) {
		String secKey = null;
		BigInteger mod = new BigInteger("00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7",16);
    	BigInteger key = new BigInteger("010001",16);
    	
		String newdata = (new StringBuffer()).append(data).reverse().toString();
		try {
			RSAPublicKeySpec keyspec = new RSAPublicKeySpec(mod, key);
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        Key publicKey = keyFactory.generatePublic(keyspec);
			Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			secKey = byte2String( cipher.doFinal(newdata.getBytes())).toLowerCase();
			secKey = format(secKey, 256);
		}catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		return secKey;
	}
	//RSA加密方法二
	public String getSecKeyBC(String data) {
		String secKey = null;
		BigInteger mod = new BigInteger("00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7",16);
    	BigInteger key = new BigInteger("010001",16);
    	
		String newdata = (new StringBuffer()).append(data).reverse().toString();
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			RSAPublicKeySpec keyspec = new RSAPublicKeySpec(mod, key);
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        Key publicKey = keyFactory.generatePublic(keyspec);
	        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding","BC");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			secKey = byte2String( cipher.doFinal(newdata.getBytes())).toLowerCase();
			secKey = format(secKey, 256);
		}catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return secKey;
	}
	//RSA加密方法三
	public String getSecKeyOriginal(String data) {
		String secKey = null;
		BigInteger mod = new BigInteger("00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7",16);
    	BigInteger key = new BigInteger("010001",16);
    	
		String newdata = (new StringBuffer()).append(data).reverse().toString();
		String src = byte2String(newdata.getBytes());
		BigInteger bigInteger1 = new BigInteger(src, 16);
		BigInteger bigInteger2 = bigInteger1.pow(key.intValue()).remainder(mod);
		secKey = byte2String(bigInteger2.toByteArray());
		secKey = format(secKey, 256);
		
		return secKey;
	}
	
	
	public static void main(String[] args) {
		NETest tn = new NETest();
		String songId = "1353372483";//; "573511899" 1353372483
		
		Map<String,String> params = tn.makePostParam(songId,"true",1);
		
		StringBuffer sb = new StringBuffer();
		sb.append("params=").append(params.get("params")).append("&encSecKey=").append(params.get("encSecKey"));
		
		System.out.println(sb.toString());
		
		String addr = "https://music.163.com/weapi/v1/resource/comments/R_SO_4_" + songId + "?csrf_token=";
		
		tn.post(songId,addr,sb.toString());

	}

}
