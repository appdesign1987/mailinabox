source setup/functions.sh # load our functions

# Basic System Configuration
# -------------------------

# ### Install Packages

# Update system packages to make sure we have the latest upstream versions of things from Ubuntu.

echo Updating system packages...
hide_output apt-get update
apt_get_quiet upgrade

# Install basic utilities.
#
# * haveged: Provides extra entropy to /dev/random so it doesn't stall
#	         when generating random numbers for private keys (e.g. during
#	         ldns-keygen).
# * unattended-upgrades: Apt tool to install security updates automatically.
# * cron: Runs background processes periodically.
# * ntp: keeps the system time correct
# * fail2ban: scans log files for repeated failed login attempts and blocks the remote IP at the firewall
# * sudo: allows privileged users to execute commands as root without being root
# * coreutils: includes `nproc` tool to report number of processors
# * bc: allows us to do math to compute sane defaults

apt_install python3 python3-dev python3-pip \
	wget curl sudo coreutils bc \
	haveged unattended-upgrades cron ntp fail2ban

# Allow apt to install system updates automatically every day.

cat > /etc/apt/apt.conf.d/02periodic <<EOF;
APT::Periodic::MaxAge "7";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Verbose "1";
EOF

# ### Firewall

# Various virtualized environments like Docker and some VPSs don't provide #NODOC
# a kernel that supports iptables. To avoid error-like output in these cases, #NODOC
# we skip this if the user sets DISABLE_FIREWALL=1. #NODOC
if [ -z "$DISABLE_FIREWALL" ]; then
	# Install `ufw` which provides a simple firewall configuration.
	apt_install ufw

	# Allow incoming connections to SSH.
	ufw_allow ssh;

	# ssh might be running on an alternate port. Use sshd -T to dump sshd's #NODOC
	# settings, find the port it is supposedly running on, and open that port #NODOC
	# too. #NODOC
	SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | sed "s/port //") #NODOC
	if [ ! -z "$SSH_PORT" ]; then
	if [ "$SSH_PORT" != "22" ]; then

	echo Opening alternate SSH port $SSH_PORT. #NODOC
	ufw_allow $SSH_PORT #NODOC

	fi
	fi

	ufw --force enable;
fi #NODOC

# ### Fail2Ban Service

# Configure the Fail2Ban installation to prevent dumb bruce-force attacks against dovecot, postfix and ssh
cp conf/fail2ban/jail.local /etc/fail2ban/jail.local
cp conf/fail2ban/dovecotimap.conf /etc/fail2ban/filter.d/dovecotimap.conf

restart_service fail2ban
