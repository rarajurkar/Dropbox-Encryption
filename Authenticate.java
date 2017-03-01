
import java.io.*;
import java.nio.ByteBuffer;
import java.security.spec.KeySpec;
import java.util.Locale;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.dropbox.core.DbxAppInfo;
import com.dropbox.core.DbxAuthFinish;
import com.dropbox.core.DbxClient;
import com.dropbox.core.DbxEntry;
import com.dropbox.core.DbxRequestConfig;
import com.dropbox.core.DbxWebAuthNoRedirect;
import com.dropbox.core.DbxWriteMode;

public class Authenticate {
	
	private static byte[][] salt = new byte[5][16];
    private static String APP_KEY;//password
    private static String APP_SECRET;//secret key
	
    public void DropboxLink(String password, String file) throws Exception {
    	
        loadSalts();
        
        APP_SECRET = generateMasterKey().toString(); 
        
        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);

        DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0",
            Locale.getDefault().toString());
        DbxWebAuthNoRedirect webAuth = new DbxWebAuthNoRedirect(config, appInfo);

        // Have the user sign in and authorize your app.
        String authorizeUrl = webAuth.start();
        System.out.println("1. Go to: " + authorizeUrl);
        System.out.println("2. Click \"Allow\" (you might have to log in first)");
        System.out.println("3. Copy the authorization code.");
        String code = new BufferedReader(new InputStreamReader(System.in)).readLine().trim();

        // This will fail if the user enters an invalid authorization code.
        DbxAuthFinish authFinish = webAuth.finish(code);
        String accessToken = authFinish.accessToken;

        DbxClient client = new DbxClient(config, accessToken);

        System.out.println("Linked account: " + client.getAccountInfo().displayName);

        File inputFile = new File(file);
        FileInputStream inputStream = new FileInputStream(inputFile);
        try {
            DbxEntry.File uploadedFile = client.uploadFile(file,
                DbxWriteMode.add(), inputFile.length(), inputStream);
            System.out.println("Uploaded: " + uploadedFile.toString());
        } finally {
            inputStream.close();
        }

        
        FileOutputStream outputStream = new FileOutputStream(file);
        try {
            DbxEntry.File downloadedFile = client.getFile(file, null,
                outputStream);
            System.out.println("Downloaded: " + downloadedFile.toString());
        } finally {
            outputStream.close();
        }
    }
    private static SecretKey generateMasterKey() throws Exception
	{
		// Generate the initial secret key from hashing the master password with the 1st salt
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keySpec1 = new PBEKeySpec(APP_KEY.toCharArray(), salt[0], 4096, 128);
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
    
    private static void loadSalts() throws IOException
	{
		FileInputStream saltInFile = new FileInputStream("C:/Users/inspiron/Dropbox/salt");
		for(int i = 0; i < salt.length; i++)
		{
			saltInFile.read(salt[i]);
		}
		saltInFile.close();
	}

}