# Basic
`ping target_ip_address`

nmap stands for Network Mapper, and it will send requests to the target's ports in hopes of receiving a reply, thus determining if the said port is open or not. Some ports are used by default by certain services. Others might be non-standard, which is why we will be using the service detection flag -sV to determine the name and description of the identified services. The text marked in green and curly brackets {} is a replacement for your own version of input. In this case, you will need to replace the {target_IP} part with the IP address of your own target.
`sudo nmap -sV target-ip`

Following the completion of the scan, we have identified port 23/tcp in an open state, running the telnet service. Following a quick Google search of this protocol, we find out that telnet is an old service used for remote management of other hosts on the network. Since the target is running this service, it can receive telnet connection requests from other hosts in the network (such as ourselves). Usually, connection requests through telnet are configured with username/password combinations for increased security. We can see this is the case for our target, as we are met with a Hack The Box banner and a request from the target to authenticate ourselves before being allowed to proceed with remote management of the target host.
`telnet ip-address`

Sometimes, due to configuration mistakes, some important accounts can be left with blank passwords for the sake of accessibility. This is a significant issue with some network devices or hosts, leaving them open to simple brute-forcing attacks, where the attacker can try logging in sequentially, using a list of usernames with no password input. Some typical important accounts have self-explanatory names, such as: admin administrator root A direct way to attempt logging in with these credentials in hopes that one of them exists and has a blank password is to input them manually in the terminal when the hosts request them. If the list were longer, we could use a script to automate this process, feeding it a wordlist for usernames and one for passwords. Typically, the wordlists used for this task consist of typical people names, abbreviations, or data from previous database leaks. For now, we can resort to manually trying these three main usernames above.
`ls
cat flag.txt`

ICMP stands for "Internet Control Message Protocol."

In order to successfully enumerate share content on the remote system, we can use a script called
smbclient . If the script is not present on your Virtual Machine, you can install it by typing the following
command in your terminal (for Debian based operating systems):
`sudo apt-get install smbclient`

Nevertheless, let us use our local username since we do not know about any remote usernames present on
the target host that we could potentially log in with. Next up, after that, we will be prompted for a password.
This password is related to the username you input before. Hypothetically, if we were a legitimate remote
user trying to log in to their resource, we would know our username and password and log in normally to
access our share. In this case, we do not have such credentials, so what we will be trying to perform is any of
the following:
Guest authentication
Anonymous authentication
Any of these will result in us logging in without knowing a proper username/password combination and
seeing the files stored on the share. Let us proceed to try that. We leave the password field blank, simply
hitting Enter to tell the script to move along.
`smbclient -L {target-ip}`


`smbclient \\\\{target_IP}\\ADMIN$`
`smbclient \\\\10.129.54.70\\WorkShares`

Once the SMB shell is killed, we can read the two documents we exfiltrated. The worknotes.txt seems to
be hinting at further services that could be exploited. Typically, these kinds of files you can find laying
around in machines within a Hack The Box Pro Lab, hinting towards your next target or being able to be
used as a resource for further exploitation or lateral movement within the lab. In our case, it is just a proof
of concept. We will not need this file.
```
exit
ls
cat worknotes.txt
cat flag.txt
```

Viewing TCP port is opening:
`nmap -p- -sV 10.129.54.204`

Installing redis-cli
Now, to be able to interact remotely with the Redis server, we need to download the redis-cli utility. It
can be downloaded using the following command :
Alternatively, we can also connect to the Redis server using the netcat utility, but we will be using rediscli in this write-up as it is more convenient to use.
Enumerating Redis Server
After successfully installing the redis-cli utility, let us view its help page by typing in the redis-cli --help command in our terminal to receive a list of all possible switches for the tool and their description.
`sudo apt install redis-tools`
`redis-cli --help`
connecting to the target computer via redis
`redis-cli -h {target-ip}`
`info`
The keyspace section provides statistics on the main dictionary of each database. The statistics include the
number of keys, and the number of keys with an expiration.
In our case, under the Keyspace section, we can see that only one database exists with index 0 .
Let us select this Redis logical database by using the select command followed by the index number of
the database that needs to be selected :
`select 0`
Furthermore, we can list all the keys present in the database using the command :
`keys *`
Finally, we can view the values stored for a corresponding key using the get command followed by the
keynote : `get <key>`
`get flag` 