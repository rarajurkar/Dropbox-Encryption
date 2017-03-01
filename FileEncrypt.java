import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class FileEncrypt {

	private static String file=null;
	private static char[] password;
	private static byte[][] salt = new byte[5][16];					// 5 password salts

	public FileEncrypt(String input, String fileToEncrypt) throws Exception {
		// TODO Auto-generated constructor stub
		password = input.toCharArray();
		file = fileToEncrypt; //
		try {
			computeHMAC();
			File saltFile = new File("C:/Users/inspiron/Dropbox/salt"); 
			boolean exists = saltFile.exists(); 
			if(!exists){
				System.out.println("Salt file intialised");
				initializeSalts();
			}
			loadSalts();
			encrypt();
			clearPasswords();
			return;
		} catch(Exception e){	// currently just catching all Exceptions here
			System.out.println("Caught error: " + e);
			e.printStackTrace();
		}

	}

	private static void computeHMAC()
	{
		try {

			StringBuffer base = new StringBuffer();
			BufferedReader read;
			read = new BufferedReader(new FileReader(file));
			String text=null;
			while((text=read.readLine())!=null)
			{
				base.append(text);
			}
			read.close();
			String baseString=base.toString();
			byte[] stringToDigest = baseString.getBytes(); // the file converted into a string to check the digest

			String keyString="integrity";
			SecretKey secretKey = null;
			byte[] keyBytes = keyString.getBytes();
			secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(secretKey);

			byte[] digest = mac.doFinal(stringToDigest);

			// format the data bytes to store as a string into database
			Formatter formatter = new Formatter();
			for (byte b : digest) {
				formatter.format("%02x", b);
			}
			String storeDigest=formatter.toString();

			//System.out.println(storeDigest);
			//  Store the digest of the file for future reference of its integrity
			// Connect to the integrity database
			Connection conn=null;
			Statement stmt= null;
			Class.forName("com.mysql.jdbc.Driver");
			conn=DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","root");
			System.out.println("Opened the Integrity Check database successfully");
			stmt=conn.createStatement();
			stmt.executeUpdate("insert into Computehash(name,storedvalue) values('"+file+"','"+ storeDigest +"');");
			//stmt.executeUpdate("insert into computehash (name) values('"+storeDigest+"');");
			System.out.println("Records inserted!!");	    
		} 
		catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();	
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}

	/**
	 * Load the existing salts from file.
	 */

	private static void initializeSalts() throws IOException
	{
		SecureRandom secureRandom = new SecureRandom();
		FileOutputStream saltOutFile = new FileOutputStream("C:/Users/inspiron/Dropbox/salt");
		for(int i = 0; i < salt.length; i++)				// store the k salts in a single file
		{
			secureRandom.nextBytes(salt[i]);
			saltOutFile.write(salt[i]);
		}
		saltOutFile.close();
	}

	private static void loadSalts() throws IOException
	{
		FileInputStream saltInFile = new FileInputStream("C:/Users/inspiron/Dropbox/salt");
		for(int i = 0; i < salt.length; i++)
		{
			saltInFile.read(salt[i]);
		}
		saltInFile.close();
	}

	/**
	 * Generate salts, hash each with master password.
	 * Save each salt to its own file.
	 * Return the master key generated from the password + salts.
	 * @return 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private static SecretKey generateMasterKey() throws Exception
	{
		// Generate the initial secret key from hashing the master password with the 1st salt
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keySpec1 = new PBEKeySpec(password, salt[0], 4096, 128);
		SecretKey secretKey1 = factory.generateSecret(keySpec1);
		SecretKey temp = secretKey1;

		for(int i = 1; i < salt.length; i++)
		{
			byte[] byteKey = temp.getEncoded();	// gets the bytes of the 1st salting

			// Convert the byte array we get from intermediate hashing into char array
			// (A char array is necessary for generating next secret key)
			ByteBuffer byteBuffer = ByteBuffer.allocate(byteKey.length);
			byteBuffer.put(byteKey);
			char[] charKey = new char[byteKey.length/2];
			for (int j = 0; j < byteKey.length; j+=2)
			{
				charKey[j/2] = (char) (byteBuffer.getChar(j));
				// alternatively could do manually without ByteBuffer
				//	charKey[j/2] = (char) ((byteKey[j] << 8) + (byteKey[j+1] & 0xFF));
			}

			// Compute the kth hash of the master key
			KeySpec keySpecK = new PBEKeySpec(charKey, salt[i], 4096, 128);
			temp = factory.generateSecret(keySpecK);
			((PBEKeySpec)keySpecK).clearPassword();
		}
		// Compute the final master key
		SecretKey masterKey = new SecretKeySpec(temp.getEncoded(), "AES");
		((PBEKeySpec)keySpec1).clearPassword();

		return masterKey;
	}

	/**
	 * Encrypt the file using AES CBC with a random file key and iv.
	 * Encrypt the file key using the master key.
	 * Write the encrypted file, the encrypted file key, and the iv.
	 * @throws Exception 
	 */
	private static void encrypt() throws Exception
	{
		// Creates the master key based on the existing salts
		SecretKey masterKey = generateMasterKey();

		// Creates file streams for the unencrypted input file and encrypted output file
		FileInputStream unencInFile = new FileInputStream(file);						// file to be encrypted
		FileOutputStream encrOutFile = new FileOutputStream("C:/Users/inspiron/Dropbox/"+file+".encrypted");		// encrypted file

		// Create AES CBC encryption cipher using Master Key as the key
		Cipher MKCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		MKCipher.init(Cipher.ENCRYPT_MODE, masterKey);
		AlgorithmParameters params = MKCipher.getParameters();

		// Create initialization vector (iv) for randomness
		IvParameterSpec ivSpec = params.getParameterSpec(IvParameterSpec.class);
		byte[] ivOut = ivSpec.getIV();

		// Save iv to file for decryption
		FileOutputStream ivOutFile = new FileOutputStream("C:/Users/inspiron/Dropbox/"+file+ ".encrypted.iv");
		ivOutFile.write(ivOut);
		ivOutFile.close();

		// Create a file key for AES
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey fileKey = keyGen.generateKey();
		byte[] fileKeyBytes = fileKey.getEncoded();
		SecretKeySpec keySpec = new SecretKeySpec(fileKeyBytes, "AES");

		// Create an AES CBC encryption cipher for file encryption
		Cipher fileCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		fileCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

		// Encrypt file using the AES CBC encryption cipher (whose key is the random file key) and write out
		byte[] tempOut = new byte[128];	// takes in the unencrypted bytes
		int byteCount;

		while ((byteCount = unencInFile.read(tempOut)) >= 0)		// read each byte of the in file into input
		{
			byte[] output = fileCipher.update(tempOut, 0, byteCount);	// holds the encrypted bytes
			if (output != null)
				encrOutFile.write(output);
		}

		byte[] output = fileCipher.doFinal();		// pads final block
		if (output != null)
			encrOutFile.write(output);

		unencInFile.close();

		encrOutFile.flush();
		encrOutFile.close();

		// Encrypt the file key using the AES CBC encryption cipher (whose key is the Master Key)
		byte[] encryptedFK = MKCipher.doFinal(fileKeyBytes);

		// Write the encrypted file key out to file for decryption
		FileOutputStream fkOutFile = new FileOutputStream("C:/Users/inspiron/Dropbox/"+file + ".encrypted.key");
		if (encryptedFK != null)
			fkOutFile.write(encryptedFK);

		fkOutFile.flush();
		fkOutFile.close();

		// Clear the fileKey byte arrays after use (both encrypted & unencrypted
		for(int i = 0; i < fileKeyBytes.length; i++)
		{
			fileKeyBytes[i] = 0;
		}
		for(int i = 0; i < encryptedFK.length; i++)
		{
			encryptedFK[i] = 0;
		}

		DropBoxSecurityTool.encrypt=true; // The file has been encrypted
	}
	
	/**
	 * Clears the password char array by zeroing out each character.
	 */
	private static void clearPasswords()
	{
		for(int i = 0; i < password.length; i++)
		{
			password[i] = 0;
		}
	}

}
