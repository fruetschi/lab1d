package at.ac.tuwien.itsfliti.securedobject;

import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.rmi.AccessException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import at.ac.tuwien.itsfliti.interfaces.IPermissionCheckProvider;
import at.ac.tuwien.itsfliti.interfaces.ITerminal;
import at.ac.tuwien.itsfliti.util.Config;

public class SecuredObject {
	private static ITerminal terminal;
	private static long lUserId;
	
	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		System.setProperty("javax.net.ssl.keyStore",
				"./res/securedobject/keystore");
		System.setProperty("javax.net.ssl.keyStorePassword",
				Config.PCP_KEYSTORE_PW);
		System.setProperty("javax.net.ssl.trustStore",
				"./res/securedobject/trustedPermCheckProv");
		System.setProperty("javax.net.ssl.trustStorePassword",
				Config.PCP_TRUSTED_PW);
		
		mock();
		
		SslRMIClientSocketFactory clientFact = new SslRMIClientSocketFactory();

		System.out.println("establishing secure connection...");
		Registry reg;
		IPermissionCheckProvider permProv = null;
		try {
			reg = LocateRegistry.getRegistry(Config.REGISTRY_HOST,
					Config.REGISTRY_PORT, clientFact);
			permProv = (IPermissionCheckProvider) reg
					.lookup(Config.PERM_CHECK_PROVIDER_BINDING_NAME);

			BufferedReader in = new BufferedReader(new InputStreamReader(
					System.in));
			// this would be not variable in a real system
			System.out.print("SecuredObjectId: ");
			long securedObjectId;
			try {
				securedObjectId = Long.parseLong(in.readLine());
			} catch(NumberFormatException nfe) {
				System.out.println("invalid id");
				return;
			} catch (IOException e) {
				return;
			}
			
			while (true) {
				// generate random challenge
				SecureRandom sr = new SecureRandom();
				byte[] challenge = new byte[32];
				sr.nextBytes(challenge);

				// send challenge to terminal and receive response
				byte[] response = terminal.authenticate(challenge);

				if(permProv.checkPermissions(securedObjectId, lUserId, challenge,
						response))
					System.out.println("access granted");
				else
					System.out.println("access denied");
			}
		} catch (AccessException e) {
			System.out.println("access to registry denied");
			return;
		} catch (RemoteException e) {
			System.out.println("could not communicate with the registry");
			return;
		} catch (NotBoundException e) {
			System.out
					.println("could not find interface of PermissionCheckProvider in the registry");
			return;
		}
	}
	
	private static PrivateKey getPrivateKey(String pathToPrivateKey) throws IOException {
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
	
	private static void mock() {
		terminal = Mockito.mock(ITerminal.class);
		given(terminal.authenticate(any(byte[].class))).willAnswer(new Answer<byte[]>() {
			@Override
			public byte[] answer(InvocationOnMock invocation)
					throws Throwable {
				BufferedReader in = new BufferedReader(new InputStreamReader(
						System.in));
				
				String userId;
				try {
					System.out.print("terminal> UserId: ");
					userId = in.readLine();
				} catch (IOException e) {
					return null;
				}
				try {
					lUserId = Long.parseLong(userId);
				} catch (NumberFormatException nfe) {
					System.out.println("terminal> ERR: invalid user id");
					return null;
				}
				PrivateKey priv;
				try {
					 priv = getPrivateKey("./res/terminal/smartcardkeys/" + lUserId + ".pem");
				} catch (IOException e) {
					System.out.println("terminal> ERR: couldn't read private key (wrong pin?)");
					return null;
				}
				
				byte[] response;
				try {
					Cipher rsaEncrypt = Cipher.getInstance(Config.RSA_CIPHER_NAME);
					rsaEncrypt.init(Cipher.ENCRYPT_MODE, priv);
					response = rsaEncrypt.doFinal((byte[]) invocation.getArguments()[0]);
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
					return null;
				} catch (NoSuchPaddingException e) {
					e.printStackTrace();
					return null;
				} catch (IllegalBlockSizeException e) {
					e.printStackTrace();
					return null;
				} catch (BadPaddingException e) {
					e.printStackTrace();
					return null;
				} catch (InvalidKeyException e) {
					e.printStackTrace();
					return null;
				}
				return response;
			}
		});
	}
}
