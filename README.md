# pytappd
Untappd Python CLI client

## History
### Version 0.9:
User lookup and checkin now return proper full objects (bug in child beer and brewery objects)
### Version 0.8:
Check in added, works. Assumes first beer by name search, otherwise search and check in by ID. Need to add venue
### Version 0.7:
FIRST VERSION THAT WORKS FROM CLI
Although you still can't check in.
Example:
```
pytappd.py  -c ../auth.ini -t beer -b "hophazardly" -a search
ID      Name    Style   Brewery Name    Brewery ID      Rating  Rating Count    In Production   Slug    Homebrew?       Created Ratings Score   Stats   Brewery Auth RatingWish List?      Media   Similar Friends Vintages
278991  Hophazardly IPA https://untappd.akamaized.net/site/beer_logos/beer-278991_d8870_sm.jpeg 7.1     0               IPA - American  None    begyle-brewing-hophazardly-ipa     None    Sat, 15 Dec 2012 18:41:36 +0000 None    None    None    None    3.75    False   None    None    None    None
```
### Version 0.6:
Set up the getBeer/getBrewery calls in the dotappd object to return actual proper objects (beer/brewwery), etc.
Create beer/brewwery/user.update() to call back to the API and fill in missing data on self.
Prep expansion of future functions
### Version 0.5:
Fix some bugs using the tool as a module.
Get actual searches working and returning valid objects
Add example code to use as module at bottom of script
### Version 0.4:
rewrite to use logging built-in.  
Move online code out of pytappd class into authenticator class.  
Rename authenticator to dotappd.
Change init of pytappd class to expect json from dotappd only.
Dump self-initialization interface
Added notes explaining how to use it right now.
beer and brewery now initalize properly from dotappd object
### Version 0.3:
semi-works as importable module, lookups of beer work and authentication works.
