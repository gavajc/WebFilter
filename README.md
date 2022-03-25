# AUTHOR

**Juan Carlos García Vázquez**

+   Date: Nov 02, 2018.
+ E-Mail: gavajc@gmail.com

# GENERAL INFO

This is a WebFilter project that works with OpenWRT embedded devices with at least 64 MB of RAM.
It also works on Linux. This project requires NetFilter Queue and libevent and at least C++11.

You can block sites by domain or by IP address or by category. You can specify some web filtering rules
as redirects or to reply to a localhost. For example, if you want to find your OpenWRT router by
domain can set a redirect rule to ping or ssh to the domain admin.webfilter.secure
or you can also access by IP address.

You can force to apply safe search on youtube, google and bing. Or limit the network bandwith.

You can create groups and apply the rules you want. (Redirections, blocks, limit bandwidth or allow by time).
To customize your settings, use the global.plc file or create a new one and specify the path to these files.
You can have as many of these files as many groups as you like.

The available categories are:

        	abortion
        	alcohol
        	audio_streaming
        	banks
        	blogs
        	chats
        	drugs
        	ecommerce
        	email
        	file_sharing
        	gambling
        	gaming
        	government
        	hacking
        	job_boards
        	lingerie_swimwear
        	news
        	p2p
        	phishing
        	porn
        	proxy
        	remote_access
        	search_engines
        	sex_education
        	social_media
        	sports
        	tobacco
        	video_streaming
        	violence
        	weapons


Categories are encrypted to save space as they use a lot of space for embedded devices. if you want them
full files please email me. In the future I will add blocking by port.

You must specify the path of the configuration file nfqueue.cfg used by this project. This file
contains the rules and paths for categories to use.

By default, the block address is the localhost IP address of your router or Linux machine.
You must have configured an http server to display the custom block page. By default, OpenWRT uses httpd.

Remember The complete list of dependencies is:


        	Netfilter Queue
        	IPTABLES
        	Libevent
        	At least  C++11
        	Add the follow iptables rules:
        
            iptables -t nat -A PREROUTING -p udp -m mark --mark 0x1 -j REDIRECT --to-ports 10053
            iptables -t nat -A PREROUTING -p udp -m mark --mark 0x2 -j REDIRECT --to-ports 10054
            iptables -t raw -A PREROUTING -j NFQUEUE --queue-num 0 --queue-bypass

    If you want to block IPV6 add the same rules for IPV6. If you don't want IPV6 add the next rule
    
        ip6tables -P FORWARD DROP

To start the project use the follow sintaxis:

    $PROG $CFG_FILE $BANDWIDTH $FILTER $NTHREADS
    
    IF BANDWIDTH is 1 apply limit bandwith rules.
    IF FILTER is 1 then apply webfilter
    On OpenWRT devices with 2 or more cores whe recommend 10 to 30 threads.
    On OpenWRT devices with 1 core only use 2 threads.

For EXAMPLE:

        $PROG             $CFG_FILE           $BANDWIDTH $FILTER $NTHREADS
    /bin/nfqueue   /etc/filtered/nfqueue.cfg      1        1        10

At this time this information is incomplete, so I will update it soon. 
If you have any questions, please email me. 
