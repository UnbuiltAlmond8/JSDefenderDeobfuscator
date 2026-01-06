# JSDefenderDeobfuscator
A tool to deobfuscate files protected by [JSDefender](https://www.preemptive.com/online-javascript-obfuscator).

> [!IMPORTANT]
> The `jsdefender.js` file is just a sample file, you have to replace it with your JSDefender obfuscated file, then run:
> - `python jsdefender-deobfuscate.py`
> 
> Node.js is required.

> [!TIP]
> In case the resulting deobfuscated file cannot be run without the obfuscated object with functions, try re-running with the argument `PROPERTY_INDIRECTION_DISABLED`.
