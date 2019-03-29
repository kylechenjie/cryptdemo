package com.richinfo.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;


/**
 * RSA测试
 *
 */
public class RSATest {

	private static String PublicKey;
	private static String PrivateKey;
	private static int KEY_SIZE = 1024;
	private static String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
	
	//生成密钥对 bc
    public static void GenerateKeyPair1() throws IOException {
    	
        RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters rsaKeyGenerationParameters = new RSAKeyGenerationParameters(BigInteger.valueOf(3), new SecureRandom(), KEY_SIZE, 25);
        rsaKeyPairGenerator.init(rsaKeyGenerationParameters);//初始化参数
        AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.generateKeyPair();
 
        AsymmetricKeyParameter publicKey = keyPair.getPublic();//公钥
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();//私钥
 
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
 
        //变字符串
        ASN1Object asn1ObjectPublic = subjectPublicKeyInfo.toASN1Primitive();
        byte[] publicInfoByte = asn1ObjectPublic.getEncoded();
        ASN1Object asn1ObjectPrivate = privateKeyInfo.toASN1Primitive();
        byte[] privateInfoByte = asn1ObjectPrivate.getEncoded();
 
        //这里可以将密钥对保存到本地
        System.out.println("PublicKey:\n" +  Base64.getEncoder().encodeToString(publicInfoByte));
        System.out.println("PrivateKey:\n" + Base64.getEncoder().encodeToString(privateInfoByte));
        
        PublicKey = Base64.getEncoder().encodeToString(publicInfoByte);
        PrivateKey = Base64.getEncoder().encodeToString(privateInfoByte);
    }
  //生成密钥对
    private static void GenerateKeyPair2() throws NoSuchAlgorithmException {  
        
        /** RSA算法要求有一个可信任的随机数源 */  
        SecureRandom secureRandom = new SecureRandom();  
          
        /** 为RSA算法创建一个KeyPairGenerator对象 */  
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");  
  
        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */  
        keyPairGenerator.initialize(KEY_SIZE, secureRandom);  
  
        /** 生成密匙对 */  
        KeyPair keyPair = keyPairGenerator.generateKeyPair();  
  
        /** 得到公钥 */  
        Key publicKey = keyPair.getPublic();  
  
        /** 得到私钥 */  
        Key privateKey = keyPair.getPrivate();  
  
        byte[] publicKeyBytes = publicKey.getEncoded();  
        byte[] privateKeyBytes = privateKey.getEncoded();  
  
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);  
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeyBytes);  
        
        System.out.println("PublicKey:" + publicKeyBase64);  
        System.out.println("PrivateKey:" + privateKeyBase64);  
        
        PublicKey = publicKeyBase64;
        PrivateKey = privateKeyBase64;
    }  
    
    public static String DealDataWithPublic(String data,String key,boolean isEncrypt) throws IOException, InvalidCipherTextException {
    	byte[] dataBytes = null;
    	//data=String.valueOf(System.currentTimeMillis())+"::"+data;
        Base64.Decoder decoder64 = Base64.getDecoder();
        Base64.Encoder encoder64 = Base64.getEncoder();
 
        AsymmetricBlockCipher cipher = new RSAEngine();
        if(!isEncrypt) {
        	dataBytes = decoder64.decode(data);
        }
 
        byte[] publicInfoBytes=decoder64.decode(key);
        ASN1Object pubKeyObj =ASN1Primitive.fromByteArray(publicInfoBytes); 
        AsymmetricKeyParameter pubKey = PublicKeyFactory.createKey(SubjectPublicKeyInfo.getInstance(pubKeyObj));
        cipher.init(isEncrypt, pubKey);//true表示加密
        
        if(isEncrypt) {
	        byte[] encryptDataBytes = cipher.processBlock(data.getBytes("utf-8"), 0, data.getBytes("utf-8").length);
	        String encryptData=encoder64.encodeToString(encryptDataBytes);
	        return  encryptData;
        }else {
        	byte[] decryptDataBytes=cipher.processBlock(dataBytes, 0, dataBytes.length);
            String decryptData = new String(decryptDataBytes,"utf-8");
            return decryptData;
        }
    }

    public static String DealDataWithPrivate(String data,String key,boolean isEncrypt) throws IOException, InvalidCipherTextException {
    	byte[] dataBytes = null;
    	Base64.Decoder decoder64 = Base64.getDecoder();
        Base64.Encoder encoder64 = Base64.getEncoder();
 
        AsymmetricBlockCipher cipher = new RSAEngine();
       
        if(!isEncrypt) {
        	dataBytes = decoder64.decode(data);
        }
 
        byte[] privateInfoByte=decoder64.decode(key);
        AsymmetricKeyParameter priKey = PrivateKeyFactory.createKey(privateInfoByte);
        cipher.init(isEncrypt, priKey);//false表示解密
        
        if(isEncrypt) {
        	 byte[] encryptDataBytes = cipher.processBlock(data.getBytes("utf-8"), 0, data.getBytes("utf-8").length);
             String encryptData=encoder64.encodeToString(encryptDataBytes);
             return  encryptData;
        }else {
        	byte[] decryptDataBytes=cipher.processBlock(dataBytes, 0, dataBytes.length);
            String decryptData = new String(decryptDataBytes,"utf-8");
            return decryptData;
        }
        
    }
    
	public static String EncryptWithPrivate(String content) throws Exception {
        byte[] data = content.getBytes();
        
        Key privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PrivateKey)));
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(1, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data));
    } 
	
	public static String DecryptWithPublic(String content) throws Exception {
		byte[] data = Base64.getDecoder().decode(content);
        Key publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PublicKey)));
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(2, publicKey);
        return new String(cipher.doFinal(data));
    } 
	
	public static String DecryptWithPrivate(String content) throws Exception {
		byte[] data = Base64.getDecoder().decode(content);
		Key privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PrivateKey)));
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(2, privateKey);
        return new String(cipher.doFinal(data));
    }
	
	public static String EncryptWithPublic(String content) throws Exception {		
		byte[] data = content.getBytes();
        Key publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PublicKey)));
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(1, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data));
    } 
    
	public static void main(String[] args) {
		try {
			System.out.println("生成秘钥对");
			GenerateKeyPair2();
			
			String content = "君不见黄河之水天上来";
			
			System.out.println("--------------------bouncycastle的RSA加解密示例--------------------");
			
			System.out.println("src:"+content);
			System.out.println("公钥加密->私钥解密");
			String enc = DealDataWithPublic(content,PublicKey,true);
			System.out.println("enc:"+enc);
			String dec = DealDataWithPrivate(enc,PrivateKey,false);
			System.out.println("dec:"+dec);
			
			System.out.println("私钥加密->公钥解密");
			enc = DealDataWithPrivate(content,PrivateKey,true);
			System.out.println("enc:"+enc);
			dec = DealDataWithPublic(enc,PublicKey,false);
			System.out.println("dec:"+dec);
			
			System.out.println("--------------------JAVA原生RSA加解密--------------------");			
					
			System.out.println("私钥加密->公钥解密");
			enc = EncryptWithPrivate(content);
			System.out.println("enc:"+enc);
			dec = DecryptWithPublic(enc);
			System.out.println("dec:"+dec);
			
			System.out.println("公钥加密->私钥解密");
			enc = EncryptWithPublic(content);
			System.out.println("enc:"+enc);
			dec = DecryptWithPrivate(enc);
			System.out.println("dec:"+dec);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		

	}

}
