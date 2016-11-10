package burp;
import burp.CSConversionFunctions;
import java.io.PrintWriter;

public class MangledInputGeneratorFactory implements IIntruderPayloadGeneratorFactory
{
	
	private IBurpExtenderCallbacks callbacks;

	public MangledInputGeneratorFactory(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	@Override
	public String getGeneratorName()
	{
	    return "Single Byte Input Mangling Generator";
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
	    IBurpExtenderCallbacks callbacks;
	    PrintWriter stdout; 
	    
	    public MangledInputPayloadGenerator(IBurpExtenderCallbacks callbacks) {
	    	this.callbacks = callbacks;
	    	this.stdout = new PrintWriter(callbacks.getStdout(), true);
	    	this.morePayloads = true;
	    	this.payloadIndex = 0;
		}


		@Override
	    public boolean hasMorePayloads()
	    {
	        return morePayloads;
	    }
	    
	    
	    @Override
	    public byte[] getNextPayload(byte[] baseValue)
	    {
	    	if (baseValue.length > 1)
		    {
		    	this.stdout.println("The base value for this generator needs to be a single ASCII character");
		    	morePayloads = false;
		    	return new byte[] {0};
		    }
	    	
	    	byte[] payload = CSConversionFunctions.characterMangler(baseValue[0], payloadIndex);
	    	payloadIndex++;
	    	if (payloadIndex == CSConversionFunctions.cmGetMaxPayloads()) morePayloads = false;
	    	return payload;
	    }
	    
	
	    @Override
	    public void reset()
	    {
	    	morePayloads = true;
	    	payloadIndex = 0;
	    }
	}

}
