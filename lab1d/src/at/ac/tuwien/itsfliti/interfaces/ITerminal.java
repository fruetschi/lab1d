package at.ac.tuwien.itsfliti.interfaces;

public interface ITerminal {
	byte[] authenticate(byte[] challenge); 
}
