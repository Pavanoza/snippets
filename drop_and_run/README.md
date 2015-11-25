drop_and_run
--
 Files:<br/>
+ main.cpp
+ resource.h
+ resource.rc
+ demo.html (the DLL to be dropped; you can substitute it by any DLL of your choice)
+ test.bat - test script to execute demo.html as a DLL
<br/>
<hr/>
what it does:<br/>
1) gets handle to demo.html (added as a resource)<br/>
2) drops it (as a hidden file)<br/>
3) loads it into memory<br/>
4) deletes the dropped file on exit<br/>

