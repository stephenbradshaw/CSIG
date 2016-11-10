package burp;

public class CSConversionFunctions {
	
	
	/**
	 * Reads UTF-8 values from a byte array. Handles overlong representations
	 * Only tested with output values <= 255
	 * Helper function used for debugging
	 * @param value - byte array to decode UTF-8 encoded value from. 
	 * @return UTF-8 code representation
	 */
	public static int readUTF8Value(byte[] value)
	{
		int out=0;
		out+=(((value[0]&255) << (6)) & 255);
		for (int i = 1; i < value.length; i++) out+=( (((value[i]&255)-128) << (6 * (value.length - i - 1))) &255);
		return out;
	}
	
	
	
	/**
	 * Prints byte arrays as binary strings
	 * Helper function used for debugging
	 * @param input - byte array
	 * @return string showing the binary value of each byte separated by " "
	 */
	public static String byteToBinaryString(byte[] input)
	{
		String out= "";
		for (byte item: input)
		{
			out += String.format("%8s", Integer.toBinaryString(item & 255)).replace(' ', '0') + " ";
		}
		return out;
	}

	

	/**
	 * Takes a single byte of input and returns a (probably) overlong UTF-8 representation of a specified length 
	 * @param input - input byte to be encoded.
	 * @param length - length of overlong representation in bytes.  Max 6.
	 * @return byte array of UTF-8 encoded value. If input < 127, or input >127 and length > 2, output will be "overlong".
	 */
	public static byte[] overlongUTF8Encoder(byte input, int length)
	{
		if (length > 6) return new byte[] {0};
		byte[] out = new byte[length];
    	out[0] = (byte)((255 << (8-length)) & 255);
    	for (int i = 1; i < length-1; i++) out[i] = (byte)(128);
    	out[length-2] = (byte)((out[length-2]&255) + ((input&255) >>> 6));
    	out[length-1] = (byte)(128 + ((input&255) & 63));
    	return out;
	}
	
	/**
	 * Flips the given zero bit to 1 within the reserved/normally unused section of UTF-8
	 * Only tested for input values to UTF-8 of 0-255.  May work for higher values, but untested! 
	 * @param input - input byte array of UTF-8 character. Can be overlong.
	 * @param bit - zero bit position, starting from MSB, to flip
	 * @return - the input array with given bit flipped to 1
	 */
	public static byte[] formatUTF8BitFlipper(byte[] input, int bit)
	{
		int fbz=(8-input.length);
		int btc = bit-fbz;
		if (btc>0)
		{
			input[btc] =  (byte)((input[btc]&255) + 64);
		}
		else
		{
			input[0] = (byte)((input[0]&255) + (1 << (fbz-bit)));
		}
		return input;
		
	}
	
	/**
	 * Returns the maximum value of payloads in the characterMangler function.
	 * Update when updating charatcerMangler
	 * @return the maximum value
	 */
	
	public static int cmGetMaxPayloads()
	{
		return 45;
	}
	
	

	/**
	 * Performs various types of mangling on an input byte value, based on payloadIndex
	 * Used as a generator for Burp Intruder, calling function should iterate from 0-max_value
	 * @param baseValue - input byte
	 * @param payloadIndex - type of mangling to perform 
	 * @return mangled payload
	 */
	public static byte[] characterMangler(byte baseValue, int payloadIndex)
	{
	    // overlong UTF-8 representions, 2 to 6 bytes
	    if (payloadIndex < 5)
	    {
	    	byte[] payload = overlongUTF8Encoder(baseValue, payloadIndex+2);
	    	return payload;
	    }
	    // additional continuation bytes on a value of 2-6 bytes
	    // trailing continuation byte is 128
	    else if (payloadIndex < 10) // start 5
	    {
	    	byte[] payload = new byte[payloadIndex-2];
	    	byte[] tarray = overlongUTF8Encoder(baseValue, payloadIndex-3);
	    	System.arraycopy(tarray, 0, payload, 0, tarray.length);
	    	payload[payload.length-1] = (byte)128;
	    	return payload;
	    }
	    // additional continuation bytes on a value of 2-6 bytes
	    // additional byte in middle
	    else if (payloadIndex < 15) // start 10
	    {
	    	byte[] payload = new byte[payloadIndex-7];
	    	byte[] tarray = overlongUTF8Encoder(baseValue, payloadIndex-8);
	    	System.arraycopy(tarray, 0, payload, 0, tarray.length);
	    	payload[payload.length-1] = payload[payload.length-2]; 
	    	payload[payload.length-2] = (byte)128;
	    	return payload;
	    }
	    // flip each reserved/normally unused zero position for 2 byte overlong encoded value
	    // covers insufficient continuation bytes plus other conditions
	    else if (payloadIndex < 21) //start 15
	    {
	    	byte[] payload = overlongUTF8Encoder(baseValue, 2);
	    	payload = formatUTF8BitFlipper(payload, payloadIndex-14);
	    	return payload;
	    }
	    // flip each reserved/normally unused zero bit for 3 byte overlong encoded value 
	    else if (payloadIndex < 27) //start 21
	    {
	    	byte[] payload = overlongUTF8Encoder(baseValue, 3);
	    	payload = formatUTF8BitFlipper(payload, payloadIndex-20);
	    	return payload;
	    }
	    // flip each reserved/normally unused zero bit for 4 byte overlong encoded value 
	    else if (payloadIndex < 33) //start 27
	    {
	    	byte[] payload = overlongUTF8Encoder(baseValue, 4);
	    	payload = formatUTF8BitFlipper(payload, payloadIndex-26);
	    	return payload;
	    }
	    // flip each reserved/normally unused" zero bit for 5 byte overlong encoded value 
	    else if (payloadIndex < 39) //start 33
	    {
	    	byte[] payload = overlongUTF8Encoder(baseValue, 5);
	    	payload = formatUTF8BitFlipper(payload, payloadIndex-32);
	    	return payload;
	    }
	    // flip each reserved/normally unused zero bit for 6 byte overlong encoded value 
	    else if (payloadIndex < 45) //start 39
	    {
	    	byte[] payload = overlongUTF8Encoder(baseValue, 6);
	    	payload = formatUTF8BitFlipper(payload, payloadIndex-38);
	    	return payload;
	    }
	    // UTF-16 BE and done
	    else // start 45
	    {
	    	byte[] payload = new byte[] {0,baseValue};
	    	return payload;
	    }
	    // max payloads of 45 at the moment
	}
	
	
}
