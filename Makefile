PREFIX = /usr/local
SYSTEMD_DIR = /usr/lib/systemd/system
PAM_DIR = /usr/lib/security

.PHONY: all install clean

all: pam_limiter.so

pam_limiter.so: pam_limiter.c
	gcc -fPIC -shared -o $@ $< -lpam

install: all
	install -m 755 pam_limiter_trigger $(PREFIX)/sbin/
	install -m 644 pam-limiter-cleanup.timer $(SYSTEMD_DIR)/
	install -m 644 pam-limiter-cleanup.service $(SYSTEMD_DIR)/
	install -m 755 pam_limiter.so $(PAM_DIR)/
	systemctl daemon-reload
	systemctl enable pam-limiter-cleanup.timer
	systemctl start pam-limiter-cleanup.timer

uninstall:
	-systemctl stop pam-limiter-cleanup.timer
	-systemctl disable pam-limiter-cleanup.timer
	-systemctl stop pam-limiter-cleanup.service
	rm -f $(PREFIX)/sbin/pam_limiter_trigger
	rm -f $(SYSTEMD_DIR)/pam-limiter-cleanup.timer
	rm -f $(SYSTEMD_DIR)/pam-limiter-cleanup.service
	rm -f $(PAM_DIR)/pam_limiter.so
	systemctl daemon-reload

clean:
	rm -f pam_limiter.so
