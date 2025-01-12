pam_limiter
===========

Block IP for about a week, using ufw, after 5 failed ssh authentication attempts from that IP within one hour.

Install
-------

```
sudo make install
```

To verify that the timer is running run
```
systemctl list-timers pam-limiter-cleanup.timer
```

Finally, add the following lines to the top of `/etc/pam.d/sshd`:
```
auth      requisite pam_limiter.so
account   optional  pam_limiter.so
```

For example, the complete `/etc/pam.d/sshd` could now look like:
```
#%PAM-1.0

# Added locally.
auth	  requisite pam_limiter.so
account	  optional  pam_limiter.so
auth	  required  pam_securetty.so    					# disable remote root
auth      required  pam_google_authenticator.so	echo_verification_code

# Original sshd:
auth      include   system-remote-login
account   include   system-remote-login
password  include   system-remote-login
session   include   system-remote-login
```

Uninstall
---------

To undo the install you can run
```
sudo make uninstall
```

First remove the added lines from `/etc/pam.d/sshd`.

Miscellaneous
-------------

To see currently banned IP's, run
```
sudo ufw status
```

To cleanup old IP's, the timer runs `/usr/local/sbin/pam-limiter-cleanup.sh`, you
can also run that manually (as root). This unblocks IP's that exist in `/var/run/pam_limiter`,
so if you reboot while certain IP's are still blocked, then the cleanup will fail.

To manually remove a blocked IP one can run:
```
sudo pam_limiter_trigger del <IP>
```

