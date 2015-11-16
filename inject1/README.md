Inject1
--
 Files:<br/>
+ main.cpp
+ main.h
+ payload.h
<br/>
<hr/>
what it does:<br/>
1) Creates a new suspended process of calc.exe - using CreateProcessW<br/>
2) Patches it's Entry Point with a shellcode, poping up a message box<br/>
3) Resumes the thread

