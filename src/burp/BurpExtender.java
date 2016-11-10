package burp;
import java.io.PrintWriter;


public class BurpExtender implements IBurpExtender
{
    private String version = "1.00";
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("CSIG");
        callbacks.registerIntruderPayloadGeneratorFactory(new SingleByteGeneratorFactory(callbacks));
        callbacks.registerIntruderPayloadGeneratorFactory(new DoubleByteGeneratorFactory(callbacks));
        callbacks.registerIntruderPayloadGeneratorFactory(new UTF8GeneratorFactory(callbacks));
        callbacks.registerIntruderPayloadGeneratorFactory(new UTF8OriginalGeneratorFactory(callbacks));
        callbacks.registerIntruderPayloadGeneratorFactory(new MangledInputGeneratorFactory(callbacks));
        callbacks.registerIntruderPayloadGeneratorFactory(new AllSingleByteMangledGeneratorFactory(callbacks));

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("CSIG " + version + " loaded!");
    }
    
}
