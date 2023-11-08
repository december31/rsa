import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MessageAuthentication {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
        String message = "I miss you!!!";
        
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(message.getBytes("UTF-8"));
        byte[] byteData = md.digest();
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            String hex = Integer.toHexString(0xff & byteData[i]);
            if (hex.length() == 1) buffer.append('0');
            buffer.append(hex);
        }
        
        System.out.println("Hex format: " + buffer.toString());
        String hashed = buffer.toString();
        
        // encrypt
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto();
        String encryptedMessage = asymmetricCrypto.encryptText(hashed, asymmetricCrypto.getPrivateKey("D:/privatekey"));

        String decryptedMessage = asymmetricCrypto.decryptText(encryptedMessage, asymmetricCrypto.getPublicKey("D:/publickey"));
        System.out.println("decryptedMessage: " + decryptedMessage);   
    }
}
