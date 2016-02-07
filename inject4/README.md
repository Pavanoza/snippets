Inject4
--
 Files:<br/>
+ main.cpp
+ main.h
<br/>
<hr/>
What it does:<br/>
1) Creates a new suspended process of calc.exe - using CreateProcessInternalW<br/>
2) Adds a new section and copy full current image there<br/>
3) Maps the new section into calc.exe<br/>
4) Applies relocations on the copied image<br/>
5) Deploys a function within the copied image from calc.exe (using <b>NtQueueApcThread</b>)<br/>
4) Resumes the main thread of calc.exe<br/>
6) Terminates the original application<br/>
<hr/>
Compile as 32 bit PE, with dynamic base. Relocation table is required for it to work.
