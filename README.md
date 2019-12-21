# Hercules
## Hercules - An alternative to Hydra

I wrote this fairly early on in my Python journey, so I apologize for the cringe-worthy lack of **PEP8** here as well as some cocky overwrites of imported module functions.  
The tool is used to target login portals where the attacker can reasonably determine a failed or successful login such that anything not matching that known request can be considered a *HIT*.  
Provide the script the **target domain/IP**, the **uripath to the portal**, a mangled set of **request parameters for the query**, and **a wordlist**.  
Then sit back and watch the fictional greek god go to work.  I based the functionality on the infamous Hydra tool.

```bash
python hercules -t localhost -u /login.php -i "username=^USER^&password=^PASS^&Submit" -f POST -l admin -P rockyou.txt -o results.out
```
