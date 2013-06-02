package at.ac.tuwien.itsfliti.interfaces;

public interface ISecuredObject {
	byte[] getChallenge();
	boolean authenticate(byte[] response, long userId);
}
