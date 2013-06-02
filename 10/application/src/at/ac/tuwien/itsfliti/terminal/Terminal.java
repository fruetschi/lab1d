package at.ac.tuwien.itsfliti.terminal;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

import at.ac.tuwien.itsfliti.interfaces.ISecuredObject;
import at.ac.tuwien.itsfliti.util.Config;

public class Terminal {
	private ISecuredObject so;
	
	public Terminal(ISecuredObject so) {
		this.so = so;
	}
	
	public void startTerminalSimulation() {
		BufferedReader in = new BufferedReader(new InputStreamReader(
				System.in));
		
		String userId;
		long lUserId;
		try {
			System.out.print("terminal> UserId: ");
			userId = in.readLine();
		} catch (IOException e) {
			return;
		}
		try {
			lUserId = Long.parseLong(userId);
		} catch (NumberFormatException nfe) {
			System.out.println("terminal> ERR: invalid user id");
			return;
		}
		
		// request challenge from securedobject
		byte[] challenge = so.getChallenge();
		
		// get encrypted challenge (in real system provided by smartcard)
		PrivateKey priv;
		try {
			 priv = getPrivateKey("./res/terminal/smartcardkeys/" + lUserId + ".pem");
		} catch (IOException e) {
			System.out.println("terminal> ERR: couldn't read private key (wrong pin?)");
			return;
		}
		
		byte[] response;
		try {
			Cipher rsaEncrypt = Cipher.getInstance(Config.RSA_CIPHER_NAME);
			rsaEncrypt.init(Cipher.ENCRYPT_MODE, priv);
			response = rsaEncrypt.doFinal(challenge);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			return;
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			return;
		} catch (BadPaddingException e) {
			e.printStackTrace();
			return;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return;
		}
		
		if(so.authenticate(response, lUserId)) {
			System.out.println("terminal> *green led*");
		} else {
			System.out.println("terminal> *red led*");
		}
	}
	
	
	private PrivateKey getPrivateKey(String pathToPrivateKey) throws IOException {
		PEMReader in = new PEMReader(new FileReader(pathToPrivateKey), new PasswordFinder() {
		    @Override
		    public char[] getPassword() {
			    // reads the password from standard input for decrypting the private key
			    System.out.print("terminal> PIN: ");
			    try {
					return new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray();
				} catch (IOException e) {
					return null;
				}
		    } 
		});

		KeyPair keyPair;
		try {
			keyPair = (KeyPair) in.readObject();
		} catch (IOException e) {
			throw new IOException("terminal> ERR: Couldn't read private key " + e.getMessage());
		} finally {
			in.close();
		}
		
		return keyPair.getPrivate();
	}
}
