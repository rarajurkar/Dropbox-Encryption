import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class FileDecrypt {


	private static char[] password;
	public static String file;
	private static byte[][] salt = new byte[5][16];					// 5 password salts

	
	public FileDecrypt(String input, String fileToEncrypt) {
		// TODO Auto-generated constructor stub
		try{
			password=input.toCharArray();
			file=fileToEncrypt;
			loadSalts();
			decrypt();	
			clearPasswords();
			return;
		}
		catch(Exception e)	// currently just catching all Exceptions here
		{
			System.out.println("Caught error: " + e);
			e.printStackTrace();
		}

	}

	
	/**
	 * Load the existing salts from file.
	 * @throws IOException 
	 */
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
	 * Decrypt the file using AES CBC with the file key and iv from file.
	 * Must first decrypt the file key using the master key.
	 * Write the decrypted file.
	 * @throws Exception 
	 */
	private static void decrypt() throws Exception 
	{
		// Creates the master key based on the existing salts
				SecretKey masterKey = generateMasterKey();

				// Create streams for the encrypted input file and the decrypted output file
				FileInputStream encrInFile = new FileInputStream("C:/Users/inspiron/Dropbox/"+file + ".encrypted"); /////////////////////////////////////
				FileOutputStream decrOutFile = new FileOutputStream("C:/Users/inspiron/Dropbox/"+file + ".decrypted");//////////////////////////////////

				// Read in the encrypted file key
				FileInputStream fkInFile = new FileInputStream("C:/Users/inspiron/Dropbox/"+file + ".encrypted.key");
				byte[] fkIn = new byte[32];
				fkInFile.read(fkIn);
				fkInFile.close();

				// Read in the iv from file
				FileInputStream ivInFile = new FileInputStream("C:/Users/inspiron/Dropbox/"+file + ".encrypted.iv");
		byte[] ivIn = new byte[16];
		ivInFile.read(ivIn);
		ivInFile.close();

		// Create an AES CBC decryption cipher (for the file key) using the master key
		Cipher keyCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		keyCipher.init(Cipher.DECRYPT_MODE, masterKey, new IvParameterSpec(ivIn));

		// Decrypt the file key (using the file key decryption cipher)
		byte[] fileKeyDecr = keyCipher.doFinal(fkIn);
		DropBoxSecurityTool.rightPassword=true;

		// Create an AES CBC decryption cipher (for the file) using the decrypted file key and iv from file
		Cipher fileCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		SecretKey fileKey = new SecretKeySpec(fileKeyDecr, "AES");
		fileCipher.init(Cipher.DECRYPT_MODE, fileKey, new IvParameterSpec(ivIn));

		// Clear the fileKey arrays after use
		for(int i = 0; i < fileKeyDecr.length; i++)
		{
			fileKeyDecr[i] = 0;
		}
		for(int i = 0; i < fkIn.length; i++)
		{
			fkIn[i] = 0;
		}

		// Decrypt the file (using the file decryption cipher)
		byte[] tempIn = new byte[128];		// takes in the encrypted bytes
		int byteCount;
		while ((byteCount = encrInFile.read(tempIn)) >= 0)
		{
			byte[] input = fileCipher.update(tempIn, 0, byteCount); 	// holds part of decryption
			if (input != null)
				decrOutFile.write(input);
		}

		byte[] output = fileCipher.doFinal();
		if (output != null)
		{
			decrOutFile.write(output);
		}
		
		encrInFile.close();
		decrOutFile.flush();
		decrOutFile.close();
		if(DropBoxSecurityTool.rightPassword==true)
		{
		computeHMAC();
		}
	}

	private static void computeHMAC()
	{
		// HMAC with SHA to store the digest of the file for future reference of its integrity

		try {
			StringBuffer base= new StringBuffer();
			BufferedReader read;
			read = new BufferedReader(new FileReader("C:/Users/inspiron/Dropbox/"+file + ".decrypted"));
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

			// format the data bytes to check against the stored hash value
			Formatter formatter = new Formatter();
			for (byte b : digest) {
				formatter.format("%02x", b);
			}
			String storeDigest=formatter.toString();
			//System.out.println(storeDigest);

			Connection conn=null;
			Statement stmt= null;
			ResultSet rs=null;
			Class.forName("com.mysql.jdbc.Driver");
			conn=DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","root");
			System.out.println("Opened the Integrity Check database successfully");
			stmt=conn.createStatement();
			rs=stmt.executeQuery("Select * from Computehash where name='"+file+"';");
			//rs=stmt.executeQuery("Select * from abc where name='"+storeDigest+"';");
			if(rs.next()){
				int index=rs.findColumn("storedvalue");
				if(storeDigest.equals(rs.getString(index))){
				System.out.println("The file integrity is checked and all seems fine.!");
				DropBoxSecurityTool.decrypt=true; // The file's integrity is fine and it has been decrypted
				}
				else
				{
					System.out.println("The file has been tampered with and this is not made available..!");
					File toDelete = new File("C:/Users/inspiron/Dropbox/"+file + ".decrypted"); // User shoould not be presented with any malicious files
					toDelete.delete();	
					DropBoxSecurityTool.close=true; // the tool has to close as the file can be malicious
				}
			}

		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

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
