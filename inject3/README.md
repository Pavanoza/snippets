Inject3
--
 Files:<br/>
+ main.cpp
+ main.h
+ payload.h
<br/>
<hr/>
What it does:<br/>
1) Creates a new suspended process of calc.exe - using CreateProcessInternalW<br/>
2) Adds a new section and copy payload there<br/>
3) Insert the shellcode to the main - thread using NtQueueApcThread<br/>
4) Resumes the main thread of calc.exe<br/>
6) Terminates the original application<br/>
<hr/>
Used functions:<br/>
+ kernel32.CreateProcessInternalW
+ ntdll.ZwCreateSection
+ ntdll.NtMapViewOfSection
+ ntdll.memcpy
+ ntdll.NtMapViewOfSection
+ ntdll.ZwUnmapViewOfSection
+ ntdll.ZwClose
+ ntdll.NtQueueApcThread
+ ntdll.ZwSetInformationThread
