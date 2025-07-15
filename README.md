Features :

- Monitor Synology NAS open ports 
- Monitor Synology NAS CPU usage and 

# Why Synaudit 

While I really love my Synoloy, the DMS inferface is slow and not easy to use for a quick audit of my system, I often had to jump between multiple services and applications just to get a broad understing of my health and security related to the nas.

Synology provides some tool, but nothing that do it quicly or bundle with eveything i have listed in the feature. 

Moreover, Synaudit is meant to be easy for non technical people and highlight security issues and recommandations often discusses with the community.

Synaudit is built using the Go langage, it's extremeley fast and does not requires any particukar knowledge

# The Synology API 

Synology offers an api that can be consumed for all sort of thing such as 

# Features 

THis is a list of rules we are doing :

- Checking firewall rules
- Checking if admin is disabled
- checking which services are open (ssh, telnet, mail ...)
- Ability to brute force the DMS login page with big leaked database
- Recommandtions based on (to be filled)
- 