# Useful URLs

**CyberChef (gchq.github.io/CyberChef/)**: to decode strings from base-64, hex and other things.

**JWT Decoder (jwt.io)**: allows to decode JWT tokens. Very useful to check headers, content structures, roles and that kind of thing.

**Online text editor (texteditor.co)**: this is useful because, copy pasting inside the environment may suck ass, so you might need to copy into this site then download it as a txt. You can then easily run it from the `Downloads` directory.

**Webhooks (webhook.site)**: Gives you an instant, unique HTTP URL and DNS endpoint to catch incoming SSRF requests, DNS pings, and exfiltrated query strings/bodies with live logs.

## Word Lists

To get **Burp Parameter List** you can run the following command:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt
```

To get the **rockyou** list, you can run:
```bash
mkdir -p ~/wordlists
curl -L -o ~/wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

To get the normally used **common.txt** you can run:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O ~/wordlists/common.txt
```

To get a deeper list, try getting the **medium.txt**:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O ~/wordlists/medium.txt
```
