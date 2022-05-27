+++
title = "HTB_CyberApocalypse2022"
date = "2022-05-27T02:31:58-04:00"
author = ""
authorTwitter = "" #do not include @
cover = ""
tags = ["", ""]
keywords = ["", ""]
description = ""
showFullContent = false
readingTime = false
hideComments = false
+++

# Cyber Apocalypse 2022 Intergalactic Chase

## Forensics
## Intergalactic Recovery

> * Miyuki’s team stores all the evidence from important cases in a shared RAID 5 disk. Especially now that the case IMW-1337 is almost completed, evidences and clues are needed more than ever. Unfortunately for the team, an electromagnetic pulse caused by Draeger’s EMP cannon has partially destroyed the disk. Can you help her and the rest of team recover the content of the failed disk? Download: http://134.209.177.115/forensics/forensics_intergalactic_recovery.zip

#### All reference links on bottom of page.

### Step 1 - Starting the challenge
After downloading and examining the file it looks like we have 3 disk.img's. <br>
<br>
So because I have no prior experience with raid I looked up a little bit about it. I decided to examine the img's to see if any of them were smaller in size. Disk 3 was only 3.7kb while disk 1 & 2 were 5mb. I assumed disk 3 was the one that needed repaired.disk.img's.

### Step 2 - Mdadm

My initial thought was to go through and try and set up the raid disk to see if it would repair its self using mdadm and losetup.

```bash
sudo apt-get install mdadm

sudo losetup /dev/loop1 disk1.img

sudo losetup /dev/loop2 disk2.img

sudo losetup /dev/loop3 disk3.img

sudo mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/loop1 /dev/loop2 /dev/loop3
```
It didn't repair itself due to the emp deleting a portion of disk 3's data as I presumed. My next thought was what if I added a disk 3a the same size as disk 1 and 2 and tried to get it to repair that way. So I ran the previous commands, but with disk 3a losetup.

```bash
sudo dd if=/dev/zero of=disk3a.img bs=5,242,880 count=1
```

This also didn't create a proper image, but I got a corrupt pdf with the name "imw_1337.pdf". After looking through the challenge description and discord I came across a hint the mods had given. "The names my not necessarily describe the order." This meant that disk 3 could actually be disk one. 

Time to get scripting...

### Step 3 - Scripting

So I made a bash script that would automate the process. It would go in to the directory, make a 3a, and create an image following a given array so that way we could get all permutations of the disks. Then delete the files, stop the loops, and unmount it. Then unzip the file and start again with brand new disks to ensure they weren't changed.

```bash
#!/bin/bash
cd ~/Desktop
unzip -q forensics_intergalactic_recovery.zip
cd forensics_intergalactic_recovery
sudo dd if=/dev/zero of=disk3a.img bs=5242880 count=1
perm=("123" "231" "312" "213" "321" "132")
for t in ${perm[@]}; do
        for i in 1 2 ; do
                sudo losetup /dev/loop${i} disk${i}.img
        done
        sudo losetup /dev/loop3 disk3a.img
        sudo mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/loop${t:0:1} /dev/loop${t:1:1} /dev/loop${t:2:1}
        read -p "Press [Enter] key to start backup..."
        sudo umount /dev/md0
        sudo mdadm --stop /dev/md0
        sudo losetup -D
        sudo losetup -a
        read -p "Press [Enter] key to start backup ..."
        cd ~/Desktop
        sudo rm -r forensics_intergalactic_recovery
        unzip -q forensics_intergalactic_recovery.zip
        cd forensics_intergalactic_recovery
        sudo dd if=/dev/zero of=disk3a.img bs=5242880 count=1
done
```

This also failed.


### Step 4 - XOR Bit by Bit

So after looking up some ctf writeups with similar problems I came across (CTF 1) It showed me that I need to XOR disk 1 & disk 2 bit by bit to get a useable disk 3. After playing around with the script shown on the writeup, my teammate M4uler had messaged me saying he had got one working.

```python
#!/usr/bin/env python3

from pwn import *

with open('disk1.img', 'rb') as f1:
    with open('disk2.img', 'rb') as f2:
        with open('disk3.img', 'wb') as f3:
            x = f1.read()
            y = f2.read()
            f3.write(xor(x,y))
```
Using this I was able to get a usable disk3.img.


### Step 5 - Getting the Flag

Using the new disk3 I got by XOR'ing disks 1 & 2 with the python script I ran a new bash script that was an edited version of the prior bash script to get all the permutations with the new disk.img. 

```bash
#!/bin/bash
cd ~/Desktop
unzip -q forensics_intergalactic_recovery.zip
cd forensics_intergalactic_recovery
perm=("123" "231" "312" "213" "321" "132")
for t in ${perm[@]}; do
        for i in 1 2 3; do
        sudo losetup /dev/loop${i} disk${i}.img
        done
        sudo mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/loop${t:0:1} /dev/loop${t:1:1} /dev/loop${t:2:1}
        read -p "Press [Enter] key to start backup..."
        sudo umount /dev/md0
        sudo mdadm --stop /dev/md0                                                                                                                                                 
        sudo losetup -D                                                                                                                                                            
        sudo losetup -a                                                                                                                                                            
        sudo rm -r forensics_intergalactic_recovery                                                                                                                                
        unzip -q forensics_intergalactic_recovery.zip
        cd forensics_intergalactic_recovery
done
```

On the second loop (Disk order 231) I got the flag.

<br>
<br>

![Flag](https://imgur.com/gallery/Zyf6P6K)

<img src="https://imgur.com/gallery/Zyf6P6K"
     alt="Flag">

##### Reference Links


[The CTF Writeup That Helped](https://itarow.xyz/posts/phack-ctf-2021_raid-dead-redemption_write-up/)
<br>
[Raid 5 Summary](https://en.wikipedia.org/wiki/RAID)

