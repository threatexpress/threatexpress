
# Clone all repos

**James Tubberville | March 13, 2019 | Tweet This Post: [:fa-twitter:](https://twitter.com/intent/tweet?url=http://threatexpress.com/blogs/2019/git-clone-entire-org/&text=Clone all repos for a specific organization.)**

![][1]

This is a short form post resulting from conversations over single line cloning and/or pulling of all organizational repos.

In short, I once needed a quick and easy bash method for pulling all repos under an organizational tree. The following three one-liners were used (and have been used many times since). I regularly use the last to pull all repos before beginning any additions or mods to ThreatExpress. 

As usual, you can find the raw script and get the latest version of tools on our GitHub repository: https://github.com/threatexpress.

---

**Clone all public repos**
```
for line in $(curl https://api.github.com/orgs/threatexpress/repos | grep -o "git@github.com:threatexpress/[^ ,\"]\+");do echo git clone $line;done
```



**Clone private repos as well**
```
for line in $(curl https://api.github.com/orgs/threatexpress/repos?access_token=<EnterTokenHere> | grep -o "git@github.com:threatexpress/[^ ,\"]\+");do git clone $line;done
```

!!!Note
    Generate your personal access token in your github profile > Developer Settings > Personal Access Tokens

---

**Pull all repos within an hierarchical folder structure**
```
find . -type d -depth 1 -exec git --git-dir={}/.git --work-tree=$PWD/{} pull \;
```


!!!Note
    I store all repos within organizational folders in a designated location. Change depth to accommodate your structure




[1]: /img/20180125_132744_attack.png
[2]: https://www.twitter.com/joevest
[3]: https://www.twitter.com/andrewchiles
[4]: https://www.twitter.com/minis_io
[5]: https://canarytokens.org/generate#
[6]: http://blog.portswigger.net/2017/07/cracking-lens-targeting-https-hidden.html
[7]: https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
[8]: http://www.exploit-monday.com/2013/04/PersistenceWithPowerShell.html
[9]: https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
[10]: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
[11]: https://github.com/HarmJ0y/CheatSheets/blob/master/PowerUp.pdf
[12]: https://github.com/HarmJ0y/CheatSheets/blob/master/PowerView.pdf
[13]: https://gist.github.com/HarmJ0y/3328d954607d71362e3c
[14]: https://adsecurity.org/?p=2362
[15]: http://blog.cobaltstrike.com/2016/07/06/gettin-down-with-aggressor-script/
[16]: https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/#respond

  