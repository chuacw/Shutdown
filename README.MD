Introduction
============
This is an application to shutdown either a local or remote Windows machine.

Usage: shutdown [[params] MACHINENAME]

&nbsp;  -a (abort current shutdown)  
&nbsp;  -f (force apps to close on shutdown)  
&nbsp;  -?,h (Show help)  
&nbsp;  -m "Message"  
&nbsp;  -r (reboot after shutdown)  
&nbsp;  -u username  
&nbsp;  -p password  
&nbsp;  -t timeout (in seconds before shutdown commences)  

MACHINENAME: LOCAL or \\remotehostname
  if MACHINENAME is empty or LOCAL, it implies the local machine

Examples
 - shutdown /?
 - shutdown -?
 - shutdown -t 5 -m "Shutting down in 5s"
 - shutdown -u "Chee Wee" -p 1234 \\\\HOST1
 - shutdown -u "Chee Wee" -p 1234 \\\\10.1.1.1
 - shutdown -a
 - shutdown -t 5 -r -f
