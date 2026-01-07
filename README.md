# JSDefenderDeobfuscator
A tool to deobfuscate files protected by [JSDefender](https://www.preemptive.com/online-javascript-obfuscator).

> [!IMPORTANT]
> The `jsdefender.js` file is just a sample file, you have to replace it with your JSDefender obfuscated file, then run:
> - `python jsdefender-deobfuscate.py`
> 
> Node.js is required.

> [!TIP]
> If you also want to unflatten the control flow without having AI do the work, consider taking a look at this existing deobfuscator:
> - https://github.com/JorianWoltjer/deobfuscate-preemptive
> 
> Note that even this existing deobfuscator is not perfect either, it won't rename variables and deal with more advanced features.
