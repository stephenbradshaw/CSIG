package burp;


public class UTF8GeneratorFactory implements IIntruderPayloadGeneratorFactory
{
	IBurpExtenderCallbacks callbacks;
	

	public UTF8GeneratorFactory(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	@Override
	public String getGeneratorName()
	{
	    return "UTF-8 RFC Characterset Generator";
	}
	
	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
	{
	    return new UTF8PayloadGenerator(this.callbacks);
	}
	
	
	class UTF8PayloadGenerator implements IIntruderPayloadGenerator
	{
	    int payloadIndex;
	    IBurpExtenderCallbacks callbacks;
	    
	    public UTF8PayloadGenerator(IBurpExtenderCallbacks callbacks) {
	    	this.callbacks = callbacks;
	    	this.payloadIndex = 0;
		}


		@Override
	    public boolean hasMorePayloads()
	    {
	        if (payloadIndex >= 1114112)
	        {
	        	return false;
	        }
	        else
	        {
	        	return true;
	        }
	    }
	    
	    
	    @Override
	    public byte[] getNextPayload(byte[] baseValue)
	    {
	    	// UTF-8 as defined by RFC-3629
	    	// its a byte stream, no need to worry about endian order
	    	
	    	// 0xxxxxxx - single byte
	        if (payloadIndex < 128)
	        {
	        	byte[] payload = new byte[1];
		        payload[0] = (byte)payloadIndex;
		        payloadIndex++;
		        return payload;
	        }
	        // 110xxxxx 10xxxxxx - double byte
	        else if (payloadIndex < 2048)
	        {
	        	byte[] payload = new byte[2];
	        	payload[0] = (byte)(192+(payloadIndex >>> 6));
	        	payload[1] = (byte)(128+(payloadIndex & 63));
	        	payloadIndex++;
	        	return payload;
	        }
	        // 1110xxxx	10xxxxxx 10xxxxxx - triple byte
	        else if (payloadIndex < 65536)
	        {
	        	byte[] payload = new byte[3];
	        	payload[0] = (byte)(224+(payloadIndex >>> 12));
	        	payload[1] = (byte)(128+((payloadIndex >>> 6) & 63));
	        	payload[2] = (byte)(128+(payloadIndex & 63));
	        	payloadIndex++;
	        	return payload;
	        }
	        // 11110xxx	10xxxxxx 10xxxxxx 10xxxxxx - quadruple byte
	        else if (payloadIndex < 1114112)
	        {
	        	byte[] payload = new byte[4];
	        	payload[0] = (byte)(240+(payloadIndex >>> 18));
	        	payload[1] = (byte)(128+((payloadIndex >>> 12) & 63));
	        	payload[2] = (byte)(128+((payloadIndex >>> 6) & 63));
	        	payload[3] = (byte)(128+(payloadIndex & 63));
	        	payloadIndex++;
	        	return payload;
	        }
	        else
	        {
	        	// whomp whomp - should not reach this point
	        	// coded this way to make character generation, ranges, etc clearer
	        	return new byte[] {0};
	        }
	        
	    }
	    
	
	    @Override
	    public void reset()
	    {
	        payloadIndex = 0;
	    }
	}

}
