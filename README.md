## CSIG

Character Set Intruder Generator

A Burp Plugin that generates various values from common character sets, for use when determining an applications response to particular character inputs, or for testing filter bypasses. Some of these payloads are extremely high volume, so may only be appropriate when running applications locally.

The following are the generators currently provided (listed in order of payload volume):

- **_Single Byte Input Mangling Generator_** - Takes the base value of the payload, which must be a single ASCII character, and mangles it in a variety of ways including overlong UTF-8 representations. Creates 45 payloads.
- **_Single Byte Characterset Generator_** - Generates each possible single byte character 0x00 - 0xff. Creates 256 payloads.
- **_All Single Byte Input Mangling Generator_** - Takes the same function from "Single Byte Input Mangling Generator", but runs it for each possible ASCII input value. Creates 11520 payloads.
- **_Double Byte Characterset Generator_** - Generates each possible double byte character combination 0x0000 - 0xffff. Creates 65536 payloads.
- **_UTF-8 RFC Characterset Generator_** - Generates each UTF-8 Character as defined by RFC-3629. Generates 1114112 payloads.
- **_UTF-8 Additional Characterset Generator (High Volume)_** - Generates UTF-8 characters outside of the range specified in RFC-3629, as per the original Ken Thompson modification. These _should not_ be considered valid by any parser made since 2003. Generates 2146369536 payloads.





### Compiling

A built version of the plugin is included in the archive, but if you want to make any changes this section provides some brief guidance on how you can recompile.

Stick burpsuite\_pro.jar into the lib folder to provide the necessary dependancies, and then use one of the following to build the CSIG.jar file.


### Using Ant
Build using Ant like so:

    ant jar


### Using Eclipse

Load into Eclipse as a project, and build as normal. The Ant build task defined in projectBuilder.xml will create the jar file.
