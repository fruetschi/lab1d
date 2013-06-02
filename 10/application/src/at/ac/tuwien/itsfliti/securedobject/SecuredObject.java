package at.ac.tuwien.itsfliti.securedobject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.SecureRandom;
import java.security.Security;

import javax.rmi.ssl.SslRMIClientSocketFactory;

import at.ac.tuwien.itsfliti.interfaces.IPermissionCheckProvider;
import at.ac.tuwien.itsfliti.interfaces.ISecuredObject;
import at.ac.tuwien.itsfliti.terminal.Terminal;
import at.ac.tuwien.itsfliti.util.Config;

public class SecuredObject implements ISecuredObject {
	private byte[] lastChallenge;
	private long securedObjectId;
	private IPermissionCheckProvider permProv = null;

	public SecuredObject(long id) throws RemoteException, NotBoundException {
		securedObjectId = id;

		SslRMIClientSocketFactory clientFact = new SslRMIClientSocketFactory();

		System.out.println("establishing secure connection...");
		Registry reg;

		reg = LocateRegistry.getRegistry(Config.REGISTRY_HOST,
				Config.REGISTRY_PORT, clientFact);
		permProv = (IPermissionCheckProvider) reg
				.lookup(Config.PERM_CHECK_PROVIDER_BINDING_NAME);
	}

	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		System.setProperty("javax.net.ssl.keyStore",
				Config.RESOURCE_DIRECTORY + "/securedobject/keystore");
		System.setProperty("javax.net.ssl.keyStorePassword",
				Config.PCP_KEYSTORE_PW);
		System.setProperty("javax.net.ssl.trustStore",
				Config.RESOURCE_DIRECTORY + "/securedobject/trustedPermCheckProv");
		System.setProperty("javax.net.ssl.trustStorePassword",
				Config.PCP_TRUSTED_PW);
		//System.setProperty("javax.net.debug", "all");

		long id;

		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		// this would not be variable in a real system
		System.out.println("SecuredObjectId: ");
		try {
			id = Long.parseLong(in.readLine());
		} catch (NumberFormatException nfe) {
			System.out.println("invalid id");
			return;
		} catch (IOException e) {
			return;
		}

		ISecuredObject so;
		try {
			so = new SecuredObject(id);
		} catch (RemoteException e) {
			System.out.println("could not communicate with the registry");
			e.printStackTrace();
			return;
		} catch (NotBoundException e) {
			System.out
					.println("could not find interface of PermissionCheckProvider in the registry");
			return;
		}
		
		Terminal t = new Terminal(so);

		while (true) {
			System.out.println("--STARTING TERMINAL SIMULATION--");
			t.startTerminalSimulation();
			System.out.println("--SIMULATION END--");
		}
	}

	@Override
	public byte[] getChallenge() {
		// generate random challenge
		SecureRandom sr = new SecureRandom();
		byte[] challenge = new byte[32];
		sr.nextBytes(challenge);
		lastChallenge = challenge;
		return challenge;
	}

	@Override
	public boolean authenticate(byte[] response, long userId) {
		try {
			if (permProv.checkPermissions(securedObjectId, userId,
					lastChallenge, response)) {
				System.out.println("unlocking door...");
				return true;
			}
		} catch (RemoteException e) {
		}
		System.out.println("authentication/authorization failed...");
		return false;
	}
}
