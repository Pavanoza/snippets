drop_and_run
--
 Files:<br/>
+ main.cpp
+ resource.h
+ resource.rc
+ picture.jpg (the DLL to be dropped; you can substitute it by any DLL of your choice)
<br/>
<hr/>
what it does:<br/>
1) gets handle to picture.jpg (added as a resource)<br/>
2) drops it under the name picture.dll (hidden file)<br/>
3) loads it into memory<br/>
4) deletes the dropped file on exit<br/>

