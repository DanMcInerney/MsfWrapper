MsfWrapper
------
Asynchronously control Metasploit with this library. For example, this will let you run commands in parallel across multiple sessions.

#### Installation
```
$ git clone https://github.com/DanMcInerney/MsfWrapper
$ cd MsfWrapper

In a new terminal: 
$ sudo msfconsole -r rpc.rc

$ pipenv install --three
$ pipenv shell
```

#### Usage
Check out the example script for how to use the API to run console commands, session commands, powershell commands, or OS shell commands.
```
Get a Windows session inside Metasploit then continue
# ./msf-api-wrapper-example.py
```
Note that the example script included here is not running asynchronously. It's using the asyncio loop because MsfrpcWrapper requires it but the example script will run synchronously.

#### Feedback
Never written a Python lib before. Please send feedback about best practices and how I'm screwing them up.
