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
	private long id;
	
	public Terminal(long id, ISecuredObject so) {
		this.so = so;
		this.id = id;
	}
	
	public void startTerminalSimulation() {
		BufferedReader in = new BufferedReader(new InputStreamReader(
				System.in));
		
		String userId;
		long lUserId;
		try {
			System.out.println("terminal> UserId: ");
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
		byte[] challenge = so.getChallenge(id);
		
		// get encrypted challenge (in real system provided by smartcard)
		PrivateKey priv;
		try {
			 priv = getPrivateKey(Config.RESOURCE_DIRECTORY + "/terminal/smartcardkeys/" + lUserId + ".pem");
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
			System.out.println("terminal> ERR: no such algorithm");
			return;
		} catch (NoSuchPaddingException e) {
			System.out.println("terminal> ERR: no such padding");
			return;
		} catch (IllegalBlockSizeException e) {
			System.out.println("terminal> ERR: illegal block size");
			return;
		} catch (BadPaddingException e) {
			System.out.println("terminal> ERR: bad padding");
			return;
		} catch (InvalidKeyException e) {
			System.out.println("terminal> ERR: invalid key");
			return;
		}
		
		if(so.authenticate(response, lUserId, id)) {
			System.out.println("terminal> *green LED*");
		} else {
			System.out.println("terminal> *red LED*");
		}
	}
	
	
	private PrivateKey getPrivateKey(String pathToPrivateKey) throws IOException {
		PEMReader in = new PEMReader(new FileReader(pathToPrivateKey), new PasswordFinder() {
		    @Override
		    public char[] getPassword() {
			    // reads the password from standard input for decrypting the private key
			    System.out.println("terminal> PIN: ");
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