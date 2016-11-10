package burp;


public class DoubleByteGeneratorFactory implements IIntruderPayloadGeneratorFactory
{
	IBurpExtenderCallbacks callbacks;

	public DoubleByteGeneratorFactory(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	@Override
	public String getGeneratorName()
	{
	    return "Double Byte Characterset Generator";
	}
	
	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
	{
	    return new DoubleBytePayloadGenerator(this.callbacks);
	}
	
	
	class DoubleBytePayloadGenerator implements IIntruderPayloadGenerator
	{
	    int payloadIndex;
	    IBurpExtenderCallbacks callbacks;
	    
	    public DoubleBytePayloadGenerator(IBurpExtenderCallbacks callbacks) {
	    	this.payloadIndex = 0;
	    	this.callbacks = callbacks;
		}


		@Override
	    public boolean hasMorePayloads()
	    {
	        if (payloadIndex >= 65536)
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
	    	byte[] payload = new byte[2];
	        payload[0] = (byte)(payloadIndex >>> 8);
	        payload[1] = (byte)(payloadIndex & 255);
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
