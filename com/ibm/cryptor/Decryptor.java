package com.ibm.cryptor;


//cc and DB2 debug... OC2
//package com.ibm.cryptor;

import com.ibm.misc.BASE64Encoder;
import com.ibm.misc.BASE64Decoder;

//import java.io.BufferedReader;
//import java.io.File;
//import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import java.util.Hashtable;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public class Decryptor {

	//public LogFile log = new LogFile();

	//private static Hashtable configValues = new Hashtable();

	//public String filePath = "c:\\Order Catcher\\";

	static private final byte[] salt =
		{
			(byte) 0xc7,
			(byte) 0x73,
			(byte) 0x21,
			(byte) 0x8c,
			(byte) 0x7e,
			(byte) 0xc8,
			(byte) 0xee,
			(byte) 0x99 };

	private static int count = 1073;

	static {
		Security.addProvider(new com.ibm.crypto.provider.IBMJCE());
	}

	/**
	 * Constructor for OrderCatcher -- debug
	 */
	public Decryptor() {
		super();
	}
	public static byte[] crypt(byte[] input, int mode) {
		byte[] result = null;
		try {
			SecretKey key = generateKey();
			PBEParameterSpec spec = new PBEParameterSpec(salt, count);
			Cipher ciph = Cipher.getInstance("PBEWithSHAAnd128bitRC4");
			ciph.init(mode, key, spec);
			result = ciph.doFinal(input);
		} catch (Exception e) {
		}
		return result;
	}
	public static byte[] decryptString(String plainText) {
		//byte[] decodedBytes = new byte[plainText.length()];
		try {
			byte[] decodedBytes = new BASE64Decoder().decodeBuffer(plainText);
			return crypt(decodedBytes, Cipher.DECRYPT_MODE);

		} 
		catch (IOException e) {
			return null;
		}
		
	}
	public static String decryptStringToString(String text) {
		return new String(decryptString(text));
	}
	public static byte[] encryptString(String plainText) {
		try {
			return crypt(plainText.getBytes("UTF8"), Cipher.ENCRYPT_MODE);
		} 
		catch (Exception e) {
			return null;
		}
	}
	public static String encryptStringToString(String plainText) {

		byte[] cipherText = encryptString(plainText);
		//String encodedString = new String();
		String encodedText = new BASE64Encoder().encodeBuffer(cipherText);
		//String encodedStrding = new String(cipherText, "UTF8");

		return encodedText;

	}
	private static SecretKey generateKey()
		throws NoSuchAlgorithmException, InvalidKeySpecException {
		//String password = (String) configValues.get("EncryptionPassword");
		String password = "b2bgateway";
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray());
		return SecretKeyFactory.getInstance("PBEWithSHAAnd128bitRC4").generateSecret(
			spec);
	}
	//	public void start() {
	//
	//		String ccNumberEncrypted = codSalesOrder.getCreditCardNumber();
	//		String ccNumber = decryptStringToString(codSalesOrder.getCreditCardNumber());
	//		
	//	}

	public static void main(String[] argv) {
		if (argv.length != 2) {
			System.err.println("Usage: Cryptor [ -d | -e ] text");
			System.exit(1);
		}

		if (argv[0].equals("-e")) {
			System.out.println(encryptStringToString(argv[1]));
		} else
			if (argv[0].equals("-d")) {
				System.out.println(decryptStringToString(argv[1]));
			}
	}
}
