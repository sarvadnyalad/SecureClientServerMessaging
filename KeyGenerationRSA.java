package java_assignment_pkg;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyGenerationRSA {

	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		//Creating Object of RSA algo
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		
		//initializing the KeyPairGenerator
		keyPairGenerator.initialize(2048);
		
		//Generating Key
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		//Extracting the private and public key from the keypair
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		
		byte[] privateKeyByte = rsaPrivateKey.getEncoded();
		byte[] publicKeyByte = rsaPublicKey.getEncoded();
		
		FileOutputStream fileOutputStream = new FileOutputStream("C:\\Users\\Vivek\\Desktop\\JavaAssignment\\"  + args[0] + ".prv");
		FileOutputStream fileOutputStream2 = new FileOutputStream("C:\\Users\\Vivek\\Desktop\\JavaAssignment\\" + args[0] + ".pub");
		fileOutputStream.write(privateKeyByte);
		fileOutputStream2.write(publicKeyByte);
		fileOutputStream.close();
		fileOutputStream2.close();
	}

}
