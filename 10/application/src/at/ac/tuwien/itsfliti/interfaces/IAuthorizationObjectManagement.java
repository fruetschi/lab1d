package at.ac.tuwien.itsfliti.interfaces;

import java.security.PublicKey;

public interface IAuthorizationObjectManagement {
	PublicKey getPublicKey(long userId);
	boolean hasAccess(long securedObjectId, long userId);
}
