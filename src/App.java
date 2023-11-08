import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import keygen.KeyPairGen;

public class App {
    public static void main(String[] args) throws Exception {
        KeyPairGen keyPairGen = new KeyPairGen(1024);
        keyPairGen.writeToFile("D:/privatekey", keyPairGen.getPrivateKey().getEncoded());
        keyPairGen.writeToFile("D:/publickey", keyPairGen.getPublicKey().getEncoded());

        String message = "I miss you!!!";
        System.out.println("Pain text: " + message);
        
        // encrypt
        String hashed = hash(message);
        System.out.println("hashed: " + hashed);
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto();
        String encryptedMessage = asymmetricCrypto.encryptText(hashed, asymmetricCrypto.getPrivateKey("D:/privatekey"));
        System.out.println("encrypted message: " + encryptedMessage);
        
        // decrypt
        String decryptedMessage = asymmetricCrypto.decryptText(encryptedMessage, asymmetricCrypto.getPublicKey("D:/publickey"));
        hashed = hash(message);
        System.out.println("hashed again: " + hashed);
        System.out.println("decryptedMessage: " + decryptedMessage);
    }

    private static String hash(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(message.getBytes("UTF-8"));
        byte[] byteData = md.digest();
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            String hex = Integer.toHexString(0xff & byteData[i]);
            if (hex.length() == 1) buffer.append('0');
            buffer.append(hex);
        }
        
        return buffer.toString();
    }
}
