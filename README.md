# pytappd
Untappd Python CLI client

#Version 0.4:
rewrite to use logging built-in.  
Move online code out of pytappd class into authenticator class.  
Rename authenticator to dotappd.
Change init of pytappd class to expect json from dotappd only.
Dump self-initialization interface
Added notes explaining how to use it right now.
beer and brewery now initalize properly from dotappd object
#Version 0.3:
semi-works as importable module, lookups of beer work and authentication works.
