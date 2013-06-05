package at.ac.tuwien.itsfliti.interfaces;

public interface ISecuredObject {
	byte[] getChallenge(long terminalId);
	boolean authenticate(byte[] response, long userId, long terminalId);
}
