package at.ac.tuwien.itsfliti.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IPermissionCheckProvider extends Remote {
	boolean checkPermissions(long securedObjectId, long terminalId, long userId, byte []challenge, byte []response) throws RemoteException;
}