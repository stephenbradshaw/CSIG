package burp;

public class SingleByteGeneratorFactory implements IIntruderPayloadGeneratorFactory
{
	IBurpExtenderCallbacks callbacks;
	
	public SingleByteGeneratorFactory(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	@Override
	public String getGeneratorName()
	{
	    return "Single Byte Characterset Generator";
	}
	
	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
	{
	    return new SingleBytePayloadGenerator(this.callbacks);
	}
	
	
	class SingleBytePayloadGenerator implements IIntruderPayloadGenerator
	{
	    int payloadIndex;
	    IBurpExtenderCallbacks callbacks;
	    
	    
	    public SingleBytePayloadGenerator(IBurpExtenderCallbacks callbacks) {
	    	this.callbacks = callbacks;
	    	this.payloadIndex = 0;
		}


		@Override
	    public boolean hasMorePayloads()
	    {
	        if (payloadIndex >= 256)
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
	        byte[] payload = new byte[1];
	        payload[0] = (byte)payloadIndex;
	        payloadIndex++;
	        return payload;
	    }
	    
	
	    @Override
	    public void reset()
	    {
	        payloadIndex = 0;
	    }
	}

}
