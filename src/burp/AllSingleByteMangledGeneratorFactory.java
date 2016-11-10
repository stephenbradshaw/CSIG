package burp;

import java.io.PrintWriter;

import burp.CSConversionFunctions;


public class AllSingleByteMangledGeneratorFactory implements IIntruderPayloadGeneratorFactory
{
	IBurpExtenderCallbacks callbacks;

	public AllSingleByteMangledGeneratorFactory(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	@Override
	public String getGeneratorName()
	{
	    return "All Single Byte Input Mangling Generator";
	}
	
	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
	{
	    return new MangledInputPayloadGenerator(this.callbacks);
	}
	
	
	class MangledInputPayloadGenerator implements IIntruderPayloadGenerator
	{
	    boolean morePayloads;
	    int payloadIndex;
	    int characterIndex;
	    IBurpExtenderCallbacks callbacks;
	    
	    
	    public MangledInputPayloadGenerator(IBurpExtenderCallbacks callbacks) {
			this.callbacks = callbacks;
			this.payloadIndex = 0;
			this.characterIndex = 0;
			this.morePayloads = true;
		}


		@Override
	    public boolean hasMorePayloads()
	    {
	        return morePayloads;
	    }
	    
	    
	    @Override
	    public byte[] getNextPayload(byte[] baseValue)
	    {
	    	byte[] payload = CSConversionFunctions.characterMangler((byte)characterIndex, payloadIndex);
	    	payloadIndex++;
	    	
	    	if (payloadIndex == CSConversionFunctions.cmGetMaxPayloads())
	    	{
	    		if (characterIndex == 255) morePayloads = false;
	    		characterIndex++;
	    		payloadIndex = 0;
	    	}
	    	return payload;
	    }
	    
	
	    @Override
	    public void reset()
	    {
	    	morePayloads = true;
	    	payloadIndex = 0;
	    	characterIndex = 0;
	    }
	}

}

