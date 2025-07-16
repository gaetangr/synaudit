Features :

- Monitor Synology NAS open ports 
- Monitor Synology NAS CPU usage and 

# Why Synaudit 

While I really love my Synoloy, the DMS inferface is slow and not easy to use for a quick audit of my system, I often had to jump between multiple services and applications just to get a broad understing of my health and security related to the nas.

Synology provides some tool, but nothing that do it quicly or bundle with eveything i have listed in the feature. 

Moreover, Synaudit is meant to be easy for non technical people and highlight security issues and recommandations often discusses with the community.

Synaudit is built using the Go langage, it's extremeley fast and does not requires any particukar knowledge

# The Synology API 

Synology offers an api that can be consumed for all sort of thing such as checking latest update, firewall rules etc, but no documentation is avaiblabe to list all endpoint with proprer parameters and description, the document available here https://kb.synology.com/fr-fr/DG/DSM_Login_Web_API_Guide/2 provides some insight in the api.

Fortunaly with a bit of reverse enegneirg, we can see that the dsm interface is using a the api in a different manner that make the consumetion much faster and easier using the compound in the body and the id key in the cookie

# Features 

THis is a list of rules we are doing :

- Checking firewall rules
- Checking if admin is disabled
- checking which services are open (ssh, telnet, mail ...)
- Ability to brute force the DMS login page with big leaked database
- Recommandtions based on (to be filled)
- 

disclaimer : to perform the security checks, an user with admin privielge is required on your synolgy nas, all networks call are made to your local nas IP, nothing is transmided, code is open source and can be check yourself.