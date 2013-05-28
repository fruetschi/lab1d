package at.ac.tuwien.itsfliti.permcheckprovider;

import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.anyLong;

import java.io.FileReader;
import java.io.IOException;
import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import org.bouncycastle.openssl.PEMReader;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import at.ac.tuwien.itsfliti.interfaces.IAuthorizationObjectManagement;
import at.ac.tuwien.itsfliti.interfaces.IPermissionCheckProvider;
import at.ac.tuwien.itsfliti.util.Config;

public class PermissionCheckProvider implements IPermissionCheckProvider {
	// stores the permissions of users to access different areas
	// format: userid, securedObjectId
	private static final int [][]userAccessTable = { {1, 5}, {1, 15}, {1, 25}, {2, 10}, {2, 20}, {2, 5}}; 
	
	private IAuthorizationObjectManagement authManagement;
	
	public PermissionCheckProvider() {
		mock();
	}
	
	public static void main(String []args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		System.setProperty("javax.net.ssl.trustStore", "./res/permcheckprovider/trustedSecObjects");
		System.setProperty("javax.net.ssl.trustStorePassword", Config.PCP_TRUSTED_PW);
		System.setProperty("javax.net.ssl.keyStore", "./res/permcheckprovider/keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", Config.PCP_KEYSTORE_PW);
		
		SslRMIClientSocketFactory clientFact = new SslRMIClientSocketFactory();
		SslRMIServerSocketFactory serverFact = new SslRMIServerSocketFactory(null, null, true);
		
		IPermissionCheckProvider permCheckProv = new PermissionCheckProvider();
		try {
			UnicastRemoteObject.exportObject(permCheckProv, 0, clientFact, serverFact);
		} catch (RemoteException e1) {
			System.out.println("couldn't export object -> server couldn't be started");
			return;
		}
		Registry reg;
		try {
			reg = LocateRegistry.createRegistry(Config.REGISTRY_PORT, clientFact, serverFact);
		} catch (RemoteException e) {
			System.out.println("could not create rmi registry");
			return;
		}
		
		try {
			reg.bind(Config.PERM_CHECK_PROVIDER_BINDING_NAME, permCheckProv);
		} catch (AccessException e) {
			System.out.println("access to registry denied");
		} catch (RemoteException e) {
			System.out.println("could not communicate with local registry");
		} catch (AlreadyBoundException e) {
			System.out.println("name is already bound");
		}
	}

	@Override
	public boolean checkPermissions(long securedObjectId, long userId, byte []challenge,
			byte []response) throws RemoteException {
		if(challenge == null || response == null)
			return false;
		PublicKey pubKey = authManagement.getPublicKey(userId);
		if(pubKey == null)
			return false;
		Cipher rsaDecrypt;
		byte []calcChallenge = null;
		try {
			rsaDecrypt = Cipher.getInstance(Config.RSA_CIPHER_NAME);
			rsaDecrypt.init(Cipher.DECRYPT_MODE, pubKey);
			calcChallenge = rsaDecrypt.doFinal(response);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
		if(calcChallenge == null)
			return false;
		
		// check if challenge response was successful
		if(!Arrays.equals(challenge, calcChallenge))
			return false;
		
		// check if userId is allowed to access the requested area
		if(!authManagement.hasAccess(securedObjectId, userId))
			return false;
		
		return true;
	}
	
	private void mock() {
		authManagement = Mockito.mock(IAuthorizationObjectManagement.class);
		given(authManagement.getPublicKey(anyLong())).willAnswer(new Answer<PublicKey>() {
			@Override
			public PublicKey answer(InvocationOnMock invocation)
					throws Throwable {
				Long id = (Long)invocation.getArguments()[0];
				PublicKey pub;
				try {
					pub = getPublicKey("./res/authobjmanagement/pubkeys/" + id + ".pub.pem");
				} catch(IOException ioe) {
					return null;
				}
				return pub;
			}
		});
		given(authManagement.hasAccess(anyLong(), anyLong())).willAnswer(new Answer<Boolean>() {
			@Override
			public Boolean answer(InvocationOnMock invocation) throws Throwable {
				Long securedObjectId = (Long) invocation.getArguments()[0];
				Long userId = (Long) invocation.getArguments()[1];
				
				for(int i = 0; i < userAccessTable.length; i++) {
					if(userAccessTable[i][0] == userId && userAccessTable[i][1] == securedObjectId)
						return true;
				}
				return false;
			}
		});
	}
	
	private PublicKey getPublicKey(String pathToPublicKey) throws IOException {
		PEMReader inPublic = new PEMReader(new FileReader(pathToPublicKey));
		PublicKey pub = (PublicKey) inPublic.readObject();
		inPublic.close();
		return pub;
	}
}
