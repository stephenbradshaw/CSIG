package burp;


public class UTF8OriginalGeneratorFactory implements IIntruderPayloadGeneratorFactory
{
	
	IBurpExtenderCallbacks callbacks;

	public UTF8OriginalGeneratorFactory(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	@Override
	public String getGeneratorName()
	{
	    return "UTF-8 Additional Characterset Generator (High Volume)";
	}
	
	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
	{
	    return new UTF8OriginalPayloadGenerator(this.callbacks);
	}
	
	
	class UTF8OriginalPayloadGenerator implements IIntruderPayloadGenerator
	{
	    long payloadIndex;
	    IBurpExtenderCallbacks callbacks;
	    
	    public UTF8OriginalPayloadGenerator(IBurpExtenderCallbacks callbacks) {
	    	this.payloadIndex = 0;
	    	this.callbacks = callbacks;
		}


		@Override
	    public boolean hasMorePayloads()
	    {
	        if (payloadIndex >= 2147483648L)
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
	    	// UTF-8 as per original Ken Thompson modification
	    	// should not be considered valid by any post 2003 parser
	    	// This only generates the values outside of the valid RFC-3629 range 
	    	// generates a shit-tonne of requests, best used locally and when you have time
	        // 11110xxx	10xxxxxx 10xxxxxx 10xxxxxx - quadruple byte
	        if (payloadIndex < 2097152)
	        {
	        	byte[] payload = new byte[4];
	        	payload[0] = (byte)(240+(payloadIndex >>> 18));
	        	payload[1] = (byte)(128+((payloadIndex >>> 12) & 63));
	        	payload[2] = (byte)(128+((payloadIndex >>> 6) & 63));
	        	payload[3] = (byte)(128+(payloadIndex & 63));
	        	payloadIndex++;
	        	return payload;
	        }
	        // 111110xx	10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx - pentuple byte
	        else if (payloadIndex < 67108864)
	        {
	        	byte[] payload = new byte[5];
	        	payload[0] = (byte)(248+(payloadIndex >>> 24));
	        	payload[1] = (byte)(128+((payloadIndex >>> 18) & 63));
	        	payload[2] = (byte)(128+((payloadIndex >>> 12) & 63));
	        	payload[3] = (byte)(128+((payloadIndex >>> 6) & 63));
	        	payload[4] = (byte)(128+(payloadIndex & 63));
	        	payloadIndex++;
	        	return payload;
	        }
	        // 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx - sextuple byte
	        else if (payloadIndex < 2147483648L)
	        {
	        	byte[] payload = new byte[6];
	        	payload[0] = (byte)(252+(payloadIndex >>> 30));
	        	payload[1] = (byte)(128+((payloadIndex >>> 24) & 63));
	        	payload[2] = (byte)(128+((payloadIndex >>> 18) & 63));
	        	payload[3] = (byte)(128+((payloadIndex >>> 12) & 63));
	        	payload[4] = (byte)(128+((payloadIndex >>> 6) & 63));
	        	payload[5] = (byte)(128+(payloadIndex & 63));
	        	payloadIndex++;
	        	return payload;
	        }
	        else
	        {
	        	// whomp whomp - should not reach this point
	        	return new byte[] {0};
	        }
	        
	    }
	    
	
	    @Override
	    public void reset()
	    {
	        payloadIndex = 1114112;
	    }
	}

}
