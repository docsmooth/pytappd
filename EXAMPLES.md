# pytappd

a CLI and python importable object for untappd manipulation


## CLI usage examples
```
$ pytappd.py  -c ../auth.ini -t beer -b "hophazardly" -a search
ID      Name    Style   Brewery Name    Brewery ID      Rating  Rating Count    In Production   Slug    Homebrew?       Created Ratings Score   Stats   Brewery Auth RatingWish List?      Media   Similar Friends Vintages
278991  Hophazardly IPA https://untappd.akamaized.net/site/beer_logos/beer-278991_d8870_sm.jpeg 7.1     0               IPA - American  None    begyle-brewing-hophazardly-ipa     None    Sat, 15 Dec 2012 18:41:36 +0000 None    None    None    None    3.75    False   None    None    None    None
```
```
$ pytappd.py -b "sierra nevada 3 weight" -t actions -a checkin --shout "From the command line to your phone line" --rating 5 --twitter
```

## object model usage

```
import pytappd
p=pytappd.dotappd("docsmooth")
p.authObject=pytappd.authObject(config="../auth.ini")

me=p.getUser("")
for b in me.recent_brews:
    print("{0}, {1}".format(b.name, b.brewery.name))

mybeers=p.searchbeer("Rogue Hop")
for i in mybeers:
    print(i.name)
    i.update(p)
    
    
    
>>> import pytappd
>>> pytappd.mylog.setLevel(pytappd.logging.WARNING)
>>> p=pytappd.dotappd("docsmooth")
>>> p.authObject=pytappd.authObject(config="../auth.ini")
>>>
>>> me=p.getUser("")
>>> for b in me.recent_brews:
...     print("{0}, {1}".format(b.name, b.brewery.name))
...
Torpedo Extra IPA, Sierra Nevada Brewing Co.
Punk Rock For Rich Kids, Solemn Oath Brewery
Coffee Stout, Sierra Nevada Brewing Co.
Flipside Red IPA, Sierra Nevada Brewing Co.
Torpedo Extra IPA, Sierra Nevada Brewing Co.
>>> me.recent_brews[0].id
4997
>>> torp=p.getBeer(4997)
>>> torp.name
'Torpedo Extra IPA'
>>> torp==me.recent_brews[0]
True
>>> breweries=p.searchbrewery("sierra Nevada")
>>> for i in breweries:
...   print("{0}, {1}".format(i.name, i.id))
...
Sierra Nevada Brewing Co., 1142
Sierra Nevada, 440698
>>> sn=p.getBrewery(1142)
>>> for i in sn.beer_list:
...   print("{0}, {1}".format(i.id, i.name))
...
6284, Pale Ale
4997, Torpedo Extra IPA
>>> sn.beer_list[1]==torp
True
>>> sn.beer_list[1]==me.recent_brews[0]
True
```

