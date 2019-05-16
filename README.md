# CVE-2019-0708


# Introduction
Microsoft has released its monthly security update for May. Included in this month's Patch Tuesday release is CVE-2019-0708, a critical remote code execution vulnerability that could allow an unauthenticated remote attacker to execute remote code on a vulnerable target running Remote Desktop Protocol (RDP). 

# Technical analysis
The vulnerability exists in the way that the RDP service handles incoming requests. An attacker can send a malicious request to the RDP service and, due to improperly sanitized request handling, the target will execute the malicious code injected into the request. CVE-2019-0708 is a pre-authentication vulnerability that requires no user interaction. The Windows versions affected are Windows XP, Windows 7, Windows Server 2003 and Windows Server 2008.
   
You can see below the number of RDP servers exposed to the Internet:
   
<p align="left">
  <img src="https://github.com/syriusbughunt/CVE-2019-0708/blob/master/img/shodan1.jpg?raw=true" width="800" title="hover text">
</p>
   
Wow, almost 4 millions RDP exposed to the Internet that are publicly available for any 0day RCE or bruteforce attacks. Now how many of them are running Windows 7 that is currently vulnerable to CVE-2019-0708? According to Shodan, there would be potentially 12,508 RDPs identified as running Windows 7. We would think that no one is stupid enough to run a RDP server exposed to the Internet with Windows XP? Wrong. More then 2,403 RDPs have been identified by Shodan running Windows XP... RIP.
   
I almost forgot, this critical bug has been an 0day for a year, it has been sold on the darknet for 500k. Details available on the following link:
   
https://habr.com/en/company/jetinfosystems/blog/451852/
   
# PoC
The famous part where probably every visit on that repo are hoping so much to find a PoC. Well, all I can give you for now is this:
   
<p align="left">
  <img src="https://github.com/syriusbughunt/CVE-2019-0708/blob/master/img/PoC_CVE-2019-0708-RDP_RCE.jpg?raw=true" width="600" title="hover text">
</p>
   
Keep on searching for technical analysis and you might find the details you need to build your own PoC. And please, we don't need a second WannaCry worm, get on the bug bounties and be useful of making the cyber space more secure.
   
# Solution
If you are running one of the OS affected by this CVE, you should be applying the full May 2019 Security Update from Microsoft. You can find below the updates that will patch this CVE:
    
https://www.catalog.update.microsoft.com/Search.aspx?q=KB4499175
