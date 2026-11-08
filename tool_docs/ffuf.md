# ffuf

ffuf is an interesting tool. It can be used to get and find possible variables that URLs take in or even endpoints. Imagine that you want to find all endpoints that an URL can take in with an ID of 1. You can construct this command:
```bash
ffuf -u http://10.110.3.72:8014/api/FUZZ/1 -w /usr/share/dirb/wordlists/common.txt
```

That command will try all of the options that exist in the file `/usr/share/dirb/wordlists/common.txt` where `FUZZ` is localted. In other words, that command with try to find all the endpoints after `/api/` that take the ID `1`.
This is the output of that ffuf command in that environment:
```
ffuf -u http://10.110.3.72:8014/api/FUZZ/1 -w /usr/share/dirb/wordlists/common.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.110.3.72:8014/api/FUZZ/1
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

users                   [Status: 200, Size: 56, Words: 1, Lines: 2, Duration: 38ms]
:: Progress: [4614/4614] :: Job [1/1] :: 1015 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

In that environment, it found that the URL `http://10.110.3.72:8014/api/users/1` returned a status `200`.



Another interesting thing you can do, is run against parameter names to try to find out if you can input extra parameters and perhaps get different outputs. To do that, you can run this command:
```bash
ffuf -u http://leak5.chal.deti:8014/api/users/7?FUZZ=1 -w ./burp-parameter-names.txt -ac
```

The output (for that environment) is the following:
```
ffuf -u http://leak5.chal.deti:8014/api/users/7?FUZZ=1 -w ./burp-parameter-names.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://leak5.chal.deti:8014/api/users/7?FUZZ=1
 :: Wordlist         : FUZZ: /home/student/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

verbose                 [Status: 200, Size: 119, Words: 1, Lines: 2, Duration: 18ms]
:: Progress: [6453/6453] :: Job [1/1] :: 1212 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

The file used could be retrieved with the following `wget`:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt
```
