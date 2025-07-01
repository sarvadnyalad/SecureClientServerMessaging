
import java.io.*;

import java.net.ServerSocket;
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
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import javax.crypto.Cipher;

public class Server {
	
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
	
	//MAIN METHOD
	public static void main(String[] args) {
		try {
			//Port
			String Port = args[0]; 
			
			//Creating a socket object
			Socket socket = null;
			
			//Creating the ServerSocket and passing the socket port number 
			ServerSocket serverSocket = new ServerSocket(Integer.parseInt(Port));
			System.out.println("Waiting for the connection........");
			
			//Data Structure for temporary store of messages by user
			List<byte[]> MessageStore = new Vector<>();
			
			while(true) {
				//SeverSocket Accepting the Request from client
				socket = serverSocket.accept();
				
				//Creating InputStream And OutputStream for Reading To/From Client
				DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
				DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
				
				while(true) {
					//For Displaying Timestamp
					LocalDate localDate = LocalDate.now();
					LocalTime localTime = LocalTime.now();
					
					//Format Specifier for Specific Format
					DateTimeFormatter DateFormatter = DateTimeFormatter.ofPattern("dd MMMM yyyy");
					DateTimeFormatter TimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
					
					//Login Date and Time
					String DateLogin = localDate.format(DateFormatter);
					String TimeLogin = localTime.format(TimeFormatter);
					
					//Reading the Message Digest of UserId Sent by client
					int length = dataInputStream.readInt();
					byte[] UserIdDigest = new byte[length];
					dataInputStream.read(UserIdDigest);
					
					//Converting it to HexaDecimal String and printing it on console
					String UserIdHexa = "";
					for(byte b:UserIdDigest) {
						UserIdHexa += String.format("%02x",b&0xFF);
					}
					System.out.println("Login From " + UserIdHexa + " on " + DateLogin + " at " + TimeLogin);
					
					//Sending the size of List Vector used to store the recipient and message to client
					int size = MessageStore.size();
					dataOutputStream.writeInt(size);
					dataOutputStream.flush();
					
					//If List Vector is not empty then entering the if condition
					if(size != 0) {
						//Extracting the Recipient from List Vector and converting it to HexaDecimalString
						byte[] RecipientByte = MessageStore.getFirst();
						byte[] PreviousUserId = MessageStore.get(1);
						String PreviousUserIdHexa = "";
						for(byte b:PreviousUserId) {
							PreviousUserIdHexa += String.format("%02x",b&0xFF);
						}
//						
						//Extracting the Message from List vector that user wanted to send to another user
						byte[] Message = MessageStore.get(2);
						
						//Checks that current userid and recipient matches or not 
						boolean IsEqual = Arrays.equals(RecipientByte, UserIdDigest);
						
						//If Matches then enters if 
						if(IsEqual == true) {
							//Sends Recipient HexaDecimal Value to Client
							dataOutputStream.writeUTF(PreviousUserIdHexa);
							
//							Updates the date & time and sends it to client
							localDate = LocalDate.now();
							localTime = LocalTime.now();
							
							String DateMessageDelivered = localDate.format(DateFormatter);
							String TimeMessageDelivered = localTime.format(TimeFormatter);
							
							dataOutputStream.writeUTF(DateMessageDelivered);
							dataOutputStream.writeUTF(TimeMessageDelivered);
							dataOutputStream.flush();
							
							//Sends the Message to Client
							dataOutputStream.writeInt(Message.length);
							dataOutputStream.write(Message);
							dataOutputStream.flush();
							
							//Generated the Signature of Encrypted Message
							byte[] PrivateKeyServer = ReadFile("server.prv");
							byte[] Signature = GenerateSignature(Message, PrivateKeyServer);
							
							
							//Send Signature of Encrypted Message to Client
							dataOutputStream.writeInt(Signature.length);
							dataOutputStream.write(Signature);
							dataOutputStream.flush();
							
							//Empty the List Vector
							MessageStore.clear();
						}
						//If the Username doesn't matches
						else
						{
							System.out.println("Invalid User");
							dataOutputStream.writeUTF("Invalid User");
							dataOutputStream.flush();
							MessageStore.clear();
							break;
						}
					}
					
					//Reading the MessageLength from client
					int EncyptedFromClientLength = dataInputStream.readInt();
					
					//Client returns the Encrypted message length as -1 if the signature verification is failed and message is corrupted
					if(EncyptedFromClientLength == -1)
					{
						System.out.println("Signature didn't verified at client side");
						continue;
					}
					
					//If Message From client is not empty enters if
					else if(EncyptedFromClientLength > 0) {
						//Reading the Message from client
						byte[] EncryptedFromClientByte = new byte[EncyptedFromClientLength];
						dataInputStream.read(EncryptedFromClientByte);
						
						//Reading the unhashed Sender's UserId
						String UnhashedUserID = dataInputStream.readUTF();
						
						//Reading the Signature that is send by Client
						int SignatureLength = dataInputStream.readInt();
						byte[] Signature = new byte[SignatureLength];
						dataInputStream.readFully(Signature);
						
						
						//Reading the Timestamp sent bye the client
						String DateMessageDelivered = dataInputStream.readUTF();
						String TimeMessageDelivered = dataInputStream.readUTF();
						
						//Verifying Signature 
						byte[] PublicKeyUser = ReadFile(UnhashedUserID + ".pub"); 
						Boolean SignatureVerification = VerifySignature(EncryptedFromClientByte, Signature, PublicKeyUser);
						if(SignatureVerification == true)
						{
							//Decrypting the Message Received from client using server's Private key
							byte[] PrivateKeyServer = ReadFile("server.prv");
							byte[] FromClientByte = GenerateDecryption(EncryptedFromClientByte,PrivateKeyServer);
							
							//Converting the Decrypted Message to String and extracting the recipient and the message
							String FromClient = new String(FromClientByte);
							int Index = FromClient.indexOf("-");
							String Recipient = FromClient.substring(0, Index);
							String RecipientAppended = "gfhk2024:" + Recipient;
							String Message = FromClient.substring(Index+1);
							
							System.out.println("Delivering a messsage to " + Recipient + " from " + UnhashedUserID + " on " + DateMessageDelivered + " at " + TimeMessageDelivered);
							System.out.println("Message is -> " + Message);
							
							//Generating the MessageDigest of Recipient
							byte[] RecipientUserDigest = GenerateMessageDigest(RecipientAppended);
							
							//Encrypting the Message with Recipient's Public Key
							byte[] PublicKeyRecipient = ReadFile(Recipient +".pub");
							byte[] MessageEncrypted = GenerateEncryption(Message, PublicKeyRecipient);	
							
							//Appending the recipient and message to List Vector
							MessageStore.add(RecipientUserDigest);
							MessageStore.add(UserIdDigest);
							MessageStore.add(MessageEncrypted);
							
						}
						
						//If Verification Fails at server side
						else
						{
							System.out.println("Signature Not Verified");
							break;
						}
					}
					//Updating the Date and Time
					localDate = LocalDate.now();
					localTime = LocalTime.now();
					String DateLogOut = localDate.format(DateFormatter);
					String TimeLogOut = localTime.format(TimeFormatter);
					System.out.println("Connection ended with " + UserIdHexa + " on " + DateLogOut + " at " + TimeLogOut);
					System.out.println();
					break;
				}
			}
		}
		catch(Exception e) {
			System.out.println("Error-> " + e.getMessage());
		}
		

	}

}
