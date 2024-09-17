---
layout: post
title: Dual Booting Kali and Parrot
date: 2024-09-17
categories:
  - cyber
comments: true
---
I recently acquired two monitors that included a laptop with it. I decided to use it as a disposable attack machine. Disposable in the sense that I can re-image it without data loss. Now, Kali or Parrot OS? I've been using HackTheBox pwnbox which is Parrot for a bit. How about both!

The GRUB boot loader has nicely supported multiple operating systems for some time. The Linux Volume Manager (LVM) allows flexible partitioning and resizing without using something like `gparted`. Key take aways are:

1. Create a LVM volume for each OS
2. Create a LVM volume for `/home` to share
3. Create the same user on each OS to make the `/home/` share work well

I'll be able to boot into either OS, upgrade them independently, and keep my data in `/home`.

The post assumes you know something of installing Linux and what partitions and LVM are. If not, there is a lot of information on this already.

# Create USB Media

I'm booting live DVDs from USB drives. Download the ISO of the desktop versions of Kali and Parrot. Write each to a USB drive using the following command. `sudo dd` is dangerous, make sure you get the devices correct or you could wipe out your hard drive.

```shell
$ sudo dd if=kali-or-parrot.iso of=/dev/usb bs=1M
```

The versions I used for this post:
- Kali 2024 W37 - [https://www.kali.org/](https://www.kali.org/)
- Parrot Live 6.1 - [https://www.parrotsec.org/download/](https://www.parrotsec.org/download/)

# Install Kali Linux

First, install Kali Linux. This is important . It has guided mode for partitioning with LVM using a separate `/home` volume. Parrot did not and I had trouble using the manual mode with LVM.

I choose "Graphical Install".

[](/assets/attachments/1225dd4485fc39f02489270b8d64d960_MD5.jpeg)
![](assets/attachments/1225dd4485fc39f02489270b8d64d960_MD5.jpeg)

Go through the install making the choices you'd like. When you get to the user name dialog, use the same user name on both Kali and Parrot. They are both Debian based, so the UID and GID will be 1000 on both operating systems. This will make the shared `/home` work seamlessly.

[](/assets/attachments/6c63768b94f841c56a8fec678cdf8d45_MD5.jpeg)
![](assets/attachments/6c63768b94f841c56a8fec678cdf8d45_MD5.jpeg)

## Partition with LVM

When you get to the following screen, pick either of the "set up LVM" options.

[](/assets/attachments/d51480cb2963e3813deca479c2c28a05_MD5.jpeg)
![](assets/attachments/d51480cb2963e3813deca479c2c28a05_MD5.jpeg)

Choose the "Separate /home partition" option. Don't try to share `/var`, and `/tmp` might be ok, but I didn't test it. You won't gain much.

[](/assets/attachments/6a803cc1db7fb093657b9de0a6fd317f_MD5.jpeg)
![](assets/attachments/6a803cc1db7fb093657b9de0a6fd317f_MD5.jpeg)

This is very important, reduce the amount of disk space used for the Kali install. This controls the total amount of space used by the logical volumes, so there will be space for the Parrot OS install. LVM allows increasing space without re-partitioning later. The home volume will get the majority of the space automatically. Leave at least 60GB for Parrot if you can spare it.

[](/assets/attachments/cd346eff0d40aa21623b9d7e8ad9f8aa_MD5.jpeg)
![](assets/attachments/cd346eff0d40aa21623b9d7e8ad9f8aa_MD5.jpeg)

Finish the Kali install with whatever options you like.

# Install Parrot OS

Boot into the Parrot OS USB. If your machine's UEFI BIOS doesn't allow you to get into it with a keypress, choose the "UEFI Firmware Settings" selection from the Kali boot screen.

[](/assets/attachments/4f25e726ab21c5cb78ae7c35cf8d678e_MD5.jpeg)
![](assets/attachments/4f25e726ab21c5cb78ae7c35cf8d678e_MD5.jpeg)

Select the "Try / Install" options.

[](/assets/attachments/abf32c1cc231fae882c446ed4df07c81_MD5.jpeg)
![](assets/attachments/abf32c1cc231fae882c446ed4df07c81_MD5.jpeg)

Run "Install Parrot".

[](/assets/attachments/ffd3bc8619b5b40fadcbad7991595a4e_MD5.jpeg)
![](assets/attachments/ffd3bc8619b5b40fadcbad7991595a4e_MD5.jpeg)

## Manual Partitioning

When you get to the "Partitions" section, choose "Manual partitioning".

[](/assets/attachments/ef05f14e9bc8f92677a715670e9e9524_MD5.jpeg)
![](assets/attachments/ef05f14e9bc8f92677a715670e9e9524_MD5.jpeg)

Edit the "/dev/kali-vg/home" volume to set the mount point to `/home`.

Create a new volume by selecting "Free Space" and "Create". This is the free space left during the Kali install.

[](/assets/attachments/11ee75ac7c7d917b7424f609bd316832_MD5.jpeg)
![](assets/attachments/11ee75ac7c7d917b7424f609bd316832_MD5.jpeg)

The default for Parrot 6.1 is "btrfs", leave it. The LVM LV name should be recognizable to you as the Parrot root partition, i.e. "parror". The mount point must be "/".

[](/assets/attachments/315c7c37eff51ec4358e297e02bbbf83_MD5.jpeg)
![](assets/attachments/315c7c37eff51ec4358e297e02bbbf83_MD5.jpeg)

Change the storage device from the volume group to the device.

[](/assets/attachments/330a6a5cd0641c42a9a6bb11328ba8d9_MD5.jpeg)
![](assets/attachments/330a6a5cd0641c42a9a6bb11328ba8d9_MD5.jpeg)

Edit the "FAT32" partition to be mounted at "/boot/efi". This is where Parrot will put the kernel and boot info.

[](/assets/attachments/f65604dfe3dd550adade0e1a47e628be_MD5.jpeg)
![](assets/attachments/f65604dfe3dd550adade0e1a47e628be_MD5.jpeg)

Make the username the same as the Kali install.

[](/assets/attachments/b9d342eb726de11d87b021c9ce34296e_MD5.jpeg)
![](assets/attachments/b9d342eb726de11d87b021c9ce34296e_MD5.jpeg)

Finish the install.

# Grub Changes

One final change I recommend when installing multiple operating systems is to disable the automatic boot. Otherwise, you'll power up your machine, grab your coffee, and too late! You need to reboot now. :p

This change needs to be made on both Kali and Parrot because `update-grub` will be run when either has a kernel upgrade.

`/etc/default/grub`:
[](/assets/attachments/b616cb76e1ddad315a3d290a057bafef_MD5.jpeg)
![](assets/attachments/b616cb76e1ddad315a3d290a057bafef_MD5.jpeg)

Then apply the change:
```shell
$ sudo update-grub
Generating grub configuration file ...
Found background image: /usr/share/images/desktop-base/desktop-grub.png
Found linux image: /boot/vmlinuz-6.5.0-13parrot1-amd64
Found initrd image: /boot/initrd.img-6.5.0-13parrot1-amd64
Warning: os-prober will be executed to detect other bootable partitions.
Its output will be used to detect bootable binaries on them and create new boot entries.
Found Kali GNU/Linux Rolling on /dev/mapper/kali--vg-root
Adding boot menu entry for UEFI Firmware Settings ...
done
```

# Dual Boot

Rebooting shows entries for Parrot and Kali!

[](/assets/attachments/b4c429534159ea7c6070124172b6706c_MD5.jpeg)
![](assets/attachments/b4c429534159ea7c6070124172b6706c_MD5.jpeg)

# Snapshots

I recommend looking into LVM snapshots. This can save you in case of a bad OS update or you happen to run something malicious. There are a few packages: `timeshift`, `snapper` and `autosnapshot`. I'm going to give `timeshift` a try first because it has a GUI with snapshot restore. It will be interesting to see how installs on both Kali and Parrot operate.
