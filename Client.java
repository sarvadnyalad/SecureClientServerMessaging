
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Scanner;

import javax.crypto.Cipher;


public class Client {
	
	//MESSAGE DIGEST METHOD
		 public static byte[] GenerateMessageDigest(String UserId) {
			try {
				byte[] PlainTextByte = UserId.getBytes();
				MessageDigest messageDigest = MessageDigest.getInstance("MD5");
				byte[] SignatureByte = messageDigest.digest(PlainTextByte);
				return SignatureByte;
			}
			catch(Exception e) {
				System.out.println("Error-> " + e.getMessage());
				return new byte[0];
			}
		}
		
		//Encryption
		public static byte[] GenerateEncryption(String PlainText,byte[] key){
			try {
				byte[] PlainTextByte = PlainText.getBytes();
				X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE,publicKey);
				byte[] CipherText = cipher.doFinal(PlainTextByte);
				return CipherText;
			}
			catch(Exception e)
			{
				System.out.println("Error-> " + e.getMessage());
				return new byte[0];
			}
		}
		
		//Decryption 
		public static byte[] GenerateDecryption(byte[] CipherText,byte[] key) {
			try {
				PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				byte[] PlainTextByte = cipher.doFinal(CipherText);
				return PlainTextByte;
			}
			catch(Exception e) {
				System.out.println("Error-> " + e.getMessage());
				return new byte[0];
			}
		}
		
		//Generating Signature
		public static byte[] GenerateSignature(byte[] ByteArray,byte[] Key ) {
			try {
				PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Key);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
				Signature signature = Signature.getInstance("SHA256withRSA");
				signature.initSign(privateKey);
				signature.update(ByteArray);
				byte[] SignatureByte = signature.sign();
				return SignatureByte;
			}
			catch(Exception e) {
				System.out.println("Error-> " + e.getMessage());
				return new byte[0];
			}
		}
		
		//Verifying Signature
		public static Boolean VerifySignature(byte[] ByteArray,byte[] SignatureByte,byte[] key) {
			try {
				X509EncodedKeySpec xoEncodedKeySpec = new X509EncodedKeySpec(key);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PublicKey publicKey = keyFactory.generatePublic(xoEncodedKeySpec);
				Signature signature = Signature.getInstance("SHA256withRSA");
				signature.initVerify(publicKey);
				signature.update(ByteArray);
				Boolean VerifiedSignatureValue = signature.verify(SignatureByte);
				return VerifiedSignatureValue;
			}
			catch(Exception e)
			{
				System.out.println("Error-> " + e.getMessage());
				return false;
			}
		}
		
		//FILE READING METHOD and providing ByteArray in return
		public static byte[] ReadFile(String FileName) {
			try {
				FileInputStream fileInputStream = new FileInputStream(FileName);
				byte[] filebytearray = new byte[fileInputStream.available()];
				fileInputStream.read(filebytearray);
				fileInputStream.close();
				return filebytearray;
			}
			catch(Exception e) {
				System.out.println("Error-> " + e.getMessage());
				return new byte[0];
			}
		}
	
	//Main Method
	public static void main(String[] args) {
		try {
			//Taking Hostname,Port and UserId from user
			String HostName = args[0];
			String Port = args[1];
			String UserId = "gfhk2024:" + args[2];
			
			//For Displaying Timestamp
			LocalDate localDate = LocalDate.now();
			LocalTime localTime = LocalTime.now();
			
			//Format Specifier for Specific Format
			DateTimeFormatter DateFormatter = DateTimeFormatter.ofPattern("dd MMMM yyyy");
			DateTimeFormatter TimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
			
			//Creating Socket for connection
			Socket socket = new Socket(HostName,Integer.parseInt(Port));
			System.out.println("Server Connected!!!");
			
			//Creating InputStream And OutputStream for Reading To/From Server
			DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
			DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
			
			//Creating Scanner for taking User Input
			Scanner scanner = new Scanner(System.in);
			
			//Message Digest of User
			byte [] UserIdDigest = GenerateMessageDigest(UserId);
			
			//Passing message Digest 
			int Length = UserIdDigest.length;
			dataOutputStream.writeInt(Length);
			dataOutputStream.write(UserIdDigest);
			
			//Reading the size of List Vector that has been sent by Server
			int size = dataInputStream.readInt();
			
			//If Size=0 print the appropriate message
			if(size == 0)
			{
				System.out.println("You Have " + size +  " Messages");
			}
			
			//Else enter the else
			else
			{
				size = size - 2;
				
				//Reading the Recipient,Date,Time sent by server
				String RecipientHexa = dataInputStream.readUTF();
				if(RecipientHexa.equalsIgnoreCase("Invalid User"))
				{
					System.out.println("Invalid User has been Entered Perviously");
					socket.close();
					scanner.close();
					return;
				}
				String Date = dataInputStream.readUTF();
				String Time = dataInputStream.readUTF();
				System.out.println("You have " + size + " Message from " + RecipientHexa + " on " + Date + " at " + Time);
				
				//Reading the EncryptedMessage Sent by user
				int EncryptedMessagelength = dataInputStream.readInt();
				byte[] EncryptedMessageUser = new byte[EncryptedMessagelength];
				dataInputStream.readFully(EncryptedMessageUser);
				
				//Reading the Signature of Encrypted Message Sent by User
				int Signaturelength = dataInputStream.readInt();
				byte[] Signature = new byte[Signaturelength];
				dataInputStream.readFully(Signature);
				
				//Verifying the Signature
				byte[] PublicKeyServer = ReadFile("server.pub");
				Boolean SignatureVerification = VerifySignature(EncryptedMessageUser, Signature, PublicKeyServer);
				
				
				if(SignatureVerification == true)
				{
					//Decrypting the Message 
					byte[] PrivateKeyUser = ReadFile(args[2] + ".prv");
					byte[] MessageUserByte = GenerateDecryption(EncryptedMessageUser, PrivateKeyUser);
					String MessageUSer = new String(MessageUserByte);
					System.out.println("Message received is -> " + MessageUSer);
				}
				
				//Send -1 to server as Verification is failed
				else
				{
					dataOutputStream.writeInt(-1);
					System.out.println("Signature Not Verified");
					socket.close();
					scanner.close();
					return;
				}
				
			}
			
			//Taking Inputs from user and working appropriately
			System.out.println("Do you Want to send the Data(Y/N): ");
			String SendData = scanner.nextLine();
			
			//If User wants to enter the message enter the if
			if(SendData.equalsIgnoreCase("Y")) {
				System.out.println("Please Enter the recipent UserId : ");
				String Recipent = scanner.nextLine();
				System.out.println("Please Enter The Data");
				String MessageToServer = scanner.nextLine();
				String ToServer = Recipent + "-" + MessageToServer;
			
				//Encrypting the message with Server's Public Key
				byte[] PublicKeyByteUserFrom = ReadFile("server.pub");
				byte[] ToServerByte = GenerateEncryption(ToServer, PublicKeyByteUserFrom);
				
				//Signature of Encrypted Message
				byte[] PrivateKeyUser = ReadFile(args[2] + ".prv");
				byte[] SignatureToServer = GenerateSignature(ToServerByte, PrivateKeyUser);
				
				//For Displaying Timestamp
				localDate = LocalDate.now();
				localTime = LocalTime.now();
				
				//Login Date and Time
				String DateMessageDelivered = localDate.format(DateFormatter);
				String TimeMessageDelivered = localTime.format(TimeFormatter);
				
				//Sending the encrypted Message to Server
				dataOutputStream.writeInt(ToServerByte.length);
				dataOutputStream.write(ToServerByte);
				dataOutputStream.flush();
				
				//Sending Signature of Encrypted Message to Server
				dataOutputStream.writeUTF(args[2]);
				dataOutputStream.writeInt(SignatureToServer.length);
				dataOutputStream.write(SignatureToServer);
				dataOutputStream.flush();
				
				//Sending MessageDelivered Date and Time
				dataOutputStream.writeUTF(DateMessageDelivered);
				dataOutputStream.writeUTF(TimeMessageDelivered);
				dataOutputStream.flush();
			}
			
			//If user don't want to send message It will Send Message Length=0 to Server 
			//This will indicate server that there is no message entered by user and client side will terminate after this 
			else {
				dataOutputStream.writeInt(0);
			}
			scanner.close();
			socket.close();
		}
		catch(Exception e) {
			System.out.println("Error-> " + e.getMessage());
		}
		

	}

}
