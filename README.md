sushi
=====

SetUid SHell Interactive - Apache Websocket Shell

using the apache websocket module create a shell plugin that can allow users / admin to open a shell
in a VT100 javascript popup.

The following vt100 javascript package works out the box and is a fork of shellinabox<BR>
http://wasd.vsm.com.au/wasd_root/src/dclinabox/readmore.html

they include a websock library and daemon that i aim to replace.

Using the apache-websockts module the dumb protocol i plan to implement the code into a plugin.</BR>
https://github.com/disconnect/apache-websocket

the plugin needs to create a thread, fork a pty running a shell and pass communication from the web socket to the pty.

sushi is a setuid wrapper similaer in purpose to suexec but with the purpose of been a "getty" it authenticates
the user against PAM and spawns login "pre authenticated" allowing better control of the process.

the wrapper is setuid/setgid [chmod 6755] and performs the following</BR>
<UL>
<LI>Authenticate the user [account/session should be opened not yet]</LI>
<LI>Make sure there is a passwd ent for the user authenticating</LI>
<LI>Initialise the groups to that of the user loging in</LI>
<LI>Some *BLACK MAGIC* if the user is a member of a SU group allow him SU access [sudo sh]</Li>
<LI>Set the ruid/guid to that of the user [possibly SU see 4]</LI>
<LI>chdir to the users home dir</LI>
</UL>

if any of these except for 4 fail the wrapper will fail this is not as "strict" as suexec nor is needed to be,
we are authenticating the user.

on success login is forked/exec we should be passing the host info and enviroment one day
waitpid will get the result code and return with it.

forkpty
=======

this is a scratch pad app eventually to be moved into a apache websockets plugin it runs sushi with forkpty
it puts STDIN into RAW mode sets the pty size to that of STDOUT.

two threads are used for IO in blocking mode as opposed to using select/O_NONBLOCK for one having std... in 
non blocking is a plan spawned by satan and we only require one thread when its put into a apach websocket plugin.

ideally as the functions are the same we could call the same function for both threads with appropriate *pvt.

forkpty accepts username and password as args that it passes to sushi these are optional and at least the password
is stupid to pass on the command line.

that said stupid is as stupid does .... so the command line of forkpty and sush is bodged so that all args vanish
as soon as possible.

the password should be passed via stdin and will be done automagically if basic auth is used for the /location in
apache.

this is very much WIP/RFC

building
========

autotools have been added for convinence please note its a "basic" setup.</br>
you need to be root to install [chown/chmod] use "sudo make install"

./configure && make && sudo make install
