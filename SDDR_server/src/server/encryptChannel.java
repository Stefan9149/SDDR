package server;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class encryptChannel {

	private static IvParameterSpec IV = new IvParameterSpec(new byte[16]);

	encryptChannel() {

	}

	public static byte[] encrypt(byte[] plainText, Key key) throws Exception {

		Cipher encryptCipher = null;

		encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		encryptCipher.init(Cipher.ENCRYPT_MODE, key, IV);

		byte[] encrypted = null;

		encrypted = encryptCipher.doFinal(plainText);

		return encrypted;
	}

	public static byte[] decrypt(byte[] cipherText, Key key) throws Exception {

		Cipher decryptCipher = null;

		decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		decryptCipher.init(Cipher.DECRYPT_MODE, key, IV);

		byte[] decrypted = null;

		decrypted = decryptCipher.doFinal(cipherText);

		return decrypted;

	}
}
