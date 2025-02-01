---
layout: post
title:  "Kasm Workspaces Offensive Toolset"
date:   2025-02-01 11:38:10 -0500
categories:
  - cyber
  - tools
comments: true
---
TL;DR: I am currently using [Kasm Workspaces](https://www.kasmweb.com/docs/latest/index.html), which is a containerized solution, for my offensive security toolset. It solves a lot of problems for me. In my [GitHub repo](https://github.com/double16/pentest-tools/) I have an Ansible playbook to install it to 99% of what I need. Others should be able to use it with little customization.

![](/assets/attachments/14124ab8e6f7635c283eb0cd81f3cff3_MD5.jpeg)

# VMs are nice, but ...

I really like virtualization and automation. IYKYK. I don't want my host cluttered with tools and config I forgot about, or a major upgrade left cruft around. Then there's the config change necessary for a CTF that breaks other stuff, but I find out it's broken weeks later and I don't know what I changed. There's always the searching to tweak things to get it just right. Now, on another host, I have to go back through the search because I forgot what I did. A VM is mostly isolated, so code gone wrong has a smaller blast radius.

Virtualization brings some challenges too. Disk space usage can get high. For assessment isolation it's best to take a snapshot of the "clean" install and then revert. I also take a snapshot before a major upgrade. So I've got a snapshot of the base install, followed by an upgrade, followed by an assessment. What if I want to work on a CTF? Stop the machine with the bug bounty work, start from a base snapshot for the CTF. How do I run both? Clone the VM, which is a lot of disk space and time. Linked clone? Ok, well, that's another layer of effective snapshots. I typically get to the point where I cannot remove old snapshots because I don't have the disk space. Delete it all, start over.

## Containers are nicer

I've used a containerized development environment before. If I can get containers running, my environment is ready to go. Most clients will allow some form of docker: Docker for Desktop, podman, docker.io on Linux or WSL, etc. How about my security toolset?

## Kasm

I stubbled across [Kasm Workspaces](https://www.kasmweb.com/docs/latest/index.html) recently. It is a Desktop-as-a-Service solution running on containers. It uses `guac` to access the desktop in a browser. It scales from a single install to a multiple server solution. This post describes what problems I want to solve and how I solved it. I use it as a single server install on my laptop with the intent of only accessing from my laptop. (It can be configured to allow connecting from other machines.)

Software is stored in a container image that includes a desktop component. Kasm provides many such "workspaces". Some are based on Ubuntu, Kali or Parrot OS. A workspace can be extended by basing a new image on an existing one. Kasm has good documentation for this.

# What am I solving for?

During my penetration testing journey, I've found the following things I want to solve:
1. Automate tool installation and configuration
2. Common resources such as wordlists, shells, etc.
3. Isolation from the host
4. Isolation between engagements: client, bug bounty, CTF
5. Ability to run engagements concurrently
6. Ephemeral: How painful is it to reinstall?
7. Persistent storage of artifacts

## Architecture

Simply put: I found I'm better off putting Kasm in a VM. It's necessary on Mac or Windows. On Linux, Kasm can be installed on the host and it's more efficient. Be careful what kind of host. If it's a managed host, I recommend using a VM anyway. If `virt-manager` is an option it's going to be very efficient anyway. EDR networking can mess with the container networking and it's ugly.

## Automate tool installation and configuration

I automate everything I can. If I do something twice, I ask myself why I didn't automate it? The dev world is full of automation: CI/CD pipelines, infrastructure-as-code (Terraform, CDK, ...), deployment. I don't like repetitive tasks. I don't like forgetting how I configured something and figuring that out again. I don't want to write a playbook of instructions to repeat. Write a script or something.

I have automated the Kasm install and configure almost entirely. I'm using [Ansible](https://github.com/ansible/ansible) for the reasons one uses Ansible. The playbook is at [https://github.com/double16/pentest-tools/tree/master/attackhost](https://github.com/double16/pentest-tools/tree/master/attackhost). Major things it does:

1. Install docker
2. Configure networking
3. Mount directories shared from the host
4. Clone git repos with fun tools into `/opt`
5. Clone wordlists into `/opt`
6. Install and configure Kasm
7. Add workspace registeries to make it easy to install workspaces
8. Configure installed workspaces with the persistent profile (if the S3 bucket is configured)

Networking: Kasm can run on multiple servers, so the different services need a way to talk to each other. It will use the laptop hostname, which will resolve to (usually) a DHCP assigned IP address. That IP address is stored and used in Kasm. When the laptop receives a new address, Kasm breaks. The networking tasks assign a local address and modify Kasm's compose config to use it for the hostname.

Kasm has workspace registries to make it easy to find and install workspaces. The `attackhost/vars/workspace_registries.yml` file contains a list of registries. Mine is in there.

I have a Kasm Workspace Registry with workspaces tailored to my liking. Kali and ParrotOS extended with packages, Burp Suite Pro and CE from Portswigger, ZAP Weekly, Postman, Caido... Read the dockerfiles for a full list. Obsidian and JetBrains IDEA.

Bloodhound is a special one. I found the docker compose version of Bloodhound to be slow to install. The workspace has it installed to the point of changing the password. It's ephemeral, so there isn't cruft from previous uses.

## Common resources such as wordlists, shells, etc.

Wordlists can be huge. Repos with tool source, like shells, can be huge. I avoid duplicating those in the Kali and Parrot images by putting them into `/opt/wordlists` and `/opt/src`. Kasm is configured to map them into all containers. These things can also be updated without requiring a new container image to be built.

## Isolation from the host

It's important to me to keep the host clean from tools and config. Using a VM does that by design. The host needs a virtualizer, such as VMware Workstation, VMware Fusion, VirtualBox, virt-manager, whatever. If a bare-metal install is used, containerization also isolates the host by design. It's a little less isolated because Kasm adds a service account for the database and a few other minor things.

## Isolation between engagements: client, bug bounty, CTF

It's imperative for engagements to not mix artifacts between each other. Scan results, exploits. Secrets would be very bad. I treat CTFs like an engagement, it forms good habits. How does the workflow support isolation?

Create a Kasm user for each engagement. The configuration that mounts volume such as the wordlists applies to all users, so no configuration for the user is needed. The usefulness of this is further described.

Persistent profiles store the home directory of the container into an S3 bucket when the workspace is removed. When the workspace is created, the profile is restored. This helps keep configuration in place. There are options to disable this feature or reset the profile when creating the workspace.

The profile is specified using a templates that allows an image and/or user to be specified in the path. It looks like `s3://my-bucket-name/profiles/{username}/{image_id}/`. The profile is scoped per user per image. Per user equates to per engagement. Per image is needed because of different software in each container image that may conflict.

## Ability to run engagements concurrently

Containerization is designed for multiple containers to run using the same image. Disk space is used efficiently. Upgrades to an image can happen while allowing existing containers to continue. Kasm will automatically remove older images that aren't in use any longer.

Using the user-per-engagement approach, multiple logins can be used with private browser windows. Logging out of a user doesn't stop the workspace, so switching users is also an option.

## Ephemeral: How painful is it to reinstall?

VMs crash. Kasm will get out of sorts sometimes from the laptop sleeping or hard poweroff. Things happen.

How painful is it? See the install section below for the steps, but my experience is 20-30 minutes for reinstall, 30 more minutes to download the images depending on network bandwidth. Not bad. I don't have to do it often. :)

## Persistent storage of artifacts

Considering the Kasm install ephemeral begs the question, what about artifacts? My setup has two options.

The playbook will mount volumes shared from the host. Reinstalling Kasm won't lose the host files and they will be available with the new install. Along with isolation, any shared directory that contains the word `share` will be configured to create a directory in the share with the user name. That user name directory is mounted. So the workspace container does not have access to the other user directories.

Kasm supports cloud storage providers. S3 is what I configure. It requires a bucket name, access key and secret. The others are more difficult when using OAuth because the laptop doesn't have a good way to receive callbacks, etc.

The S3 integration using `rclone` to mount the bucket at `/s3`. It works fairly well. There are some filesystem consistency issues, but I haven't lost data. See the `rclone` docs for details. The S3 volume doesn't support specifying paths like the persistent profiles do. Using an S3 bucket doesn't nicely isolate engagements like the host shares.

There is a `/mnt/user_share` directory that is mounted to the VM at `/home/kasm_user_share`. It has subdirectories for each Kasm user (engagement). Don't use it for stuff that is important long term, or at least do a good job of keeping the VM healthy.

# Install

I'm assuming the reader understands how to install a VM and configure the OS.

I recommend the VM have at least 120GB of disk space. 200GB is better. The disk usage is stable, it doesn't grow much over time. Most of the space is the container images which are automatically cleaned by Kasm. Workspaces with lots of data stored outside of the volume mounts (shared folders, S3) will take up space but will be cleaned on removal.

I set memory to 2/3 of system memory, and cores to half of the total. YMMV.

For VMWare there is a script in the repo `new-vm-vmware.sh` that will create a new VM, auto-provision Ubuntu, and use btrfs with compression. Filesystem compression helps noticeably for the container images. The script will create a new SSH key, configure it in the VM, then configure a `.hosts.ini` file for use with Ansible.

The install requires some files ignored by `git` that are specific to the install. The playbook will create examples if they aren't found, except for `.hosts.ini`.

| file                              | purpose                                                            |
| --------------------------------- | ------------------------------------------------------------------ |
| `attackhost/.hosts.ini`           | Ansible hosts config                                               |
| `vars/.networking-{hostname}.yml` | Settings for a local network to survive DHCP IP address changes    |
| `vars/.credentials.yml`           | Credentials for Kasm, S3, etc. to remain stable across re-installs |

The command for running the playbook follows.

```shell
$ cd pentest-tools/attackhost

$ ansible-playbook --ask-become-pass -i .hosts.ini kasm.yaml
# ansible will stop requesting the configuration in `vars/.credentials.yml` to be updated

$ ansible-playbook --ask-become-pass -i .hosts.ini kasm.yaml
# kasm is installed, login as admin@kasm.local and install the desired workspaces

$ ansible-playbook --ask-become-pass -i .hosts.ini kasm.yaml
# now the installed workspaces will have persistent profiles configured
```

## `.hosts.ini`

`hosts.ini` has an example. Ignore `[kasm_build]` and `[kasm_agents]`. `[kasm_build]` is for the image build VM, which has specific requires for multi-platform builds. It's not needed for use. `[kasm_agents]` is a work in progress that may not ever be.

The IP address is that of the VM used for ssh.

```
[kasm_server]
192.168.1.100 ansible_user=your_username ansible_ssh_private_key_file=~/.ssh/id_kasm

# 127.0.0.1 ansible_connection=local
```

## `vars/.networking-{hostname}.yml`

This file is automatically generated. There shouldn't be a need to modify it.

```yaml
kasm_server_ip: "169.254.213.100"
```

## `vars/.credentials.yml`

The `generated` values will contain values that the playbook populates. User `admin@kasm.local` and `admin_password` are used for administration. The `user_password` is used for user logins. The other passwords and tokens are used internally.

`storage_key`, `storage_secret` and `storage_bucket` are the S3 config that is used for both persistent profiles and the S3 volume mount. If S3 isn't desired, replace `CHANGEME` with empty strings.

`kasm_users` isn't required, but can be used for users to provision by automation. The default user group is configured so that each user doesn't require specific configuration.

```yaml
admin_password: "generated"
user_password: "generated"
manager_token: "generated"
database_password: "generated"
redis_password: "generated"
registration_token: "generated"
storage_key: "CHANGEME"
storage_secret: "CHANGEME"
storage_bucket: "CHANGEME" 
kasm_users: "test,engagement1,engagement2,ctf1,ctf2"
```

# User Experience

What is the workflow like?

![](/assets/attachments/d5f44ec6bd8a3928d9bc35761262274c_MD5.jpeg)

![](/assets/attachments/47f191e52062b69101489f7c51281143_MD5.jpeg)

![](/assets/attachments/101d616a055db381ce975b9d9dd45b98_MD5.jpeg)

![](/assets/attachments/0716cfb4ba1babcb38ede0292686a277_MD5.jpeg)

The response is really good. IMHO it feels like typing on the host terminal.

Kasm has a control panel that can be expanded. "Workspaces" will minimize the workspace and allow others to be launcher. "Delete Session" will destroy it, saving the persistent profile.

![](/assets/attachments/883f53474afdfb7460aa46c3dc8615ab_MD5.jpeg)

The [Kasm docs](https://www.kasmweb.com/docs/latest/index.html) are very good. Read through them to understand other features.

# Reinstalling

Ansible can be used to uninstall and reinstall Kasm if the VM is ok, but Kasm is broken in some way.

```shell
$ ansible-playbook --ask-become-pass -i .hosts.ini kasm-uninstall.yaml
# kasm is uninstalled, containers may need to be forcibly removed in the VM

$ ansible-playbook --ask-become-pass -i .hosts.ini kasm.yaml
# kasm is installed, login as admin@kasm.local and install the desired workspaces

$ ansible-playbook --ask-become-pass -i .hosts.ini kasm.yaml
# now the installed workspaces will have persistent profiles configured
```

# Warnings

## Kasm is Desktop-as-a-Service

This means it is primarily intended to allow connections from other computers to run desktops. Only port 443 is needed. Bind it to the loopback device. Or block it with the firewall. Careful with EDR and running afoul of policies. Running in a VM with NAT networking and forwarding only port 443 on loopback will help.

## Kasm touchs users and docker

Kasm adds a service account for the database. It installs some plugins into docker. There are some packages it needs. If these modifications will trigger the EDR, best to use a VM that may lessen the issue.

## Lock-down Profile Storage

Persistent profiles will very likely have sensitive data such as secrets. Secure the S3 bucket, or don't use persistent profiles.

An example bucket policy is in the repo at `attackhost/kasm-s3-storage-policy.json`.
