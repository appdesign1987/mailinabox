#!/usr/bin/python3
#
# Checks that the upstream DNS has been set correctly and that
# SSL certificates have been signed, etc., and if not tells the user
# what to do next.

__ALL__ = ['check_certificate']

import os, os.path, re, subprocess, datetime, multiprocessing.pool


import dateutil.parser, dateutil.tz

from web_update import get_web_domains, get_domain_ssl_files
from mailconfig import get_mail_domains, get_mail_aliases

from utils import shell, sort_domains, load_env_vars_from_file

def run_checks(env, output, pool):
	# run systems checks
	output.add_heading("System")

	# check that services are running
	if not run_services_checks(env, output, pool):
		# If critical services are not running, stop. If bind9 isn't running,
		# all later DNS checks will timeout and that will take forever to
		# go through, and if running over the web will cause a fastcgi timeout.
		return

	# clear bind9's DNS cache so our DNS checks are up to date
	# (ignore errors; if bind9/rndc isn't running we'd already report
	# that in run_services checks.)
	shell('check_call', ["/usr/sbin/rndc", "flush"], trap=True)
	
	run_system_checks(env, output)

	# perform other checks asynchronously

	run_network_checks(env, output)
	run_domain_checks(env, output, pool)

def get_ssh_port():
    # Returns ssh port
    output = shell('check_output', ['sshd', '-T'])
    returnNext = False

    for e in output.split():
        if returnNext:
            return int(e)
        if e == "port":
            returnNext = True

def run_services_checks(env, output, pool):
	# Check that system services are running.

	services = [
		
		
		
		{ "name": "Dovecot LMTP LDA", "port": 10026, "public": False, },
		{ "name": "Postgrey", "port": 10023, "public": False, },
		{ "name": "Spamassassin", "port": 10025, "public": False, },
		{ "name": "OpenDKIM", "port": 8891, "public": False, },
		{ "name": "OpenDMARC", "port": 8893, "public": False, },
		{ "name": "Memcached", "port": 11211, "public": False, },
		{ "name": "Sieve (dovecot)", "port": 4190, "public": False, },
		{ "name": "Mail-in-a-Box Management Daemon", "port": 10222, "public": False, },

		{ "name": "SSH Login (ssh)", "port": get_ssh_port(), "public": True, },
	
		{ "name": "Incoming Mail (SMTP/postfix)", "port": 25, "public": True, },
		{ "name": "Outgoing Mail (SMTP 587/postfix)", "port": 587, "public": True, },
		
		{ "name": "IMAPS (dovecot)", "port": 993, "public": True, },
		{ "name": "HTTP Web (nginx)", "port": 80, "public": True, },
		{ "name": "HTTPS Web (nginx)", "port": 443, "public": True, },
	]

	all_running = True
	fatal = False
	ret = pool.starmap(check_service, ((i, service, env) for i, service in enumerate(services)), chunksize=1)
	for i, running, fatal2, output2 in sorted(ret):
		all_running = all_running and running
		fatal = fatal or fatal2
		output2.playback(output)

	if all_running:
		output.print_ok("All system services are running.")

	return not fatal

def check_service(i, service, env):
	import socket
	output = BufferedOutput()
	running = False
	fatal = False
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	try:
		try:
			s.connect((
				"127.0.0.1" if not service["public"] else env['PUBLIC_IP'],
				service["port"]))
			running = True
		except OSError as e1:
			if service["public"] and service["port"] != 53:
				# For public services (except DNS), try the private IP as a fallback.
				s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s1.settimeout(1)
				try:
					s1.connect(("127.0.0.1", service["port"]))
					output.print_error("%s is running but is not publicly accessible at %s:%d (%s)." % (service['name'], env['PUBLIC_IP'], service['port'], str(e1)))
				except:
					raise e1
				finally:
					s1.close()
			else:
				raise

	except OSError as e:
		output.print_error("%s is not running (%s; port %d)." % (service['name'], str(e), service['port']))

		# Why is nginx not running?
		if service["port"] in (80, 443):
			output.print_line(shell('check_output', ['nginx', '-t'], capture_stderr=True, trap=True)[1].strip())

		# Flag if local DNS is not running.
		if service["port"] == 53 and service["public"] == False:
			fatal = True
	finally:
		s.close()

	return (i, running, fatal, output)

def run_system_checks(env, output):
	check_ssh_password(env, output)
	check_software_updates(env, output)
	check_system_aliases(env, output)
	check_free_disk_space(env, output)

def check_ssh_password(env, output):
	# Check that SSH login with password is disabled. The openssh-server
	# package may not be installed so check that before trying to access
	# the configuration file.
	if not os.path.exists("/etc/ssh/sshd_config"):
		return
	sshd = open("/etc/ssh/sshd_config").read()
	if re.search("\nPasswordAuthentication\s+yes", sshd) \
		or not re.search("\nPasswordAuthentication\s+no", sshd):
		output.print_error("""The SSH server on this machine permits password-based login. A more secure
			way to log in is using a public key. Add your SSH public key to $HOME/.ssh/authorized_keys, check
			that you can log in without a password, set the option 'PasswordAuthentication no' in
			/etc/ssh/sshd_config, and then restart the openssh via 'sudo service ssh restart'.""")
	else:
		output.print_ok("SSH disallows password-based login.")

def check_software_updates(env, output):
	# Check for any software package updates.
	pkgs = list_apt_updates(apt_update=False)
	if os.path.exists("/var/run/reboot-required"):
		output.print_error("System updates have been installed and a reboot of the machine is required.")
	elif len(pkgs) == 0:
		output.print_ok("System software is up to date.")
	else:
		output.print_error("There are %d software packages that can be updated." % len(pkgs))
		for p in pkgs:
			output.print_line("%s (%s)" % (p["package"], p["version"]))

def check_system_aliases(env, output):
	# Check that the administrator alias exists since that's where all
	# admin email is automatically directed.
	check_alias_exists("administrator@" + env['PRIMARY_HOSTNAME'], env, output)

def check_free_disk_space(env, output):
	# Check free disk space.
	st = os.statvfs(env['STORAGE_ROOT'])
	bytes_total = st.f_blocks * st.f_frsize
	bytes_free = st.f_bavail * st.f_frsize
	disk_msg = "The disk has %s GB space remaining." % str(round(bytes_free/1024.0/1024.0/1024.0*10.0)/10.0)
	if bytes_free > .3 * bytes_total:
		output.print_ok(disk_msg)
	elif bytes_free > .15 * bytes_total:
		output.print_warning(disk_msg)
	else:
		output.print_error(disk_msg)

def run_network_checks(env, output):
	# Also see setup/network-checks.sh.

	output.add_heading("Network")

	# Stop if we cannot make an outbound connection on port 25. Many residential
	# networks block outbound port 25 to prevent their network from sending spam.
	# See if we can reach one of Google's MTAs with a 5-second timeout.
	code, ret = shell("check_call", ["/bin/nc", "-z", "-w5", "aspmx.l.google.com", "25"], trap=True)
	if ret == 0:
		output.print_ok("Outbound mail (SMTP port 25) is not blocked.")
	else:
		output.print_error("""Outbound mail (SMTP port 25) seems to be blocked by your network. You
			will not be able to send any mail. Many residential networks block port 25 to prevent hijacked
			machines from being able to send spam. A quick connection test to Google's mail server on port 25
			failed.""")

	# Stop if the IPv4 address is listed in the ZEN Spamhaus Block List.
	# The user might have ended up on an IP address that was previously in use
	# by a spammer, or the user may be deploying on a residential network. We
	# will not be able to reliably send mail in these cases.
	rev_ip4 = ".".join(reversed(env['PUBLIC_IP'].split('.')))
	zen = query_dns(rev_ip4+'.zen.spamhaus.org', 'A', nxdomain=None)
	if zen is None:
		output.print_ok("IP address is not blacklisted by zen.spamhaus.org.")
	else:
		output.print_error("""The IP address of this machine %s is listed in the Spamhaus Block List (code %s),
			which may prevent recipients from receiving your email. See http://www.spamhaus.org/query/ip/%s."""
			% (env['PUBLIC_IP'], zen, env['PUBLIC_IP']))



def check_alias_exists(alias, env, output):
	mail_alises = dict(get_mail_aliases(env))
	if alias in mail_alises:
		output.print_ok("%s exists as a mail alias [=> %s]" % (alias, mail_alises[alias]))
	else:
		output.print_error("""You must add a mail alias for %s and direct email to you or another administrator.""" % alias)

def check_mail_domain(domain, env, output):
	# Check the MX record.

	recommended_mx = "10 " + env['PRIMARY_HOSTNAME']
	mx = query_dns(domain, "MX", nxdomain=None)

	if mx is None:
		mxhost = None
	else:
		# query_dns returns a semicolon-delimited list
		# of priority-host pairs.
		mxhost = mx.split('; ')[0].split(' ')[1]

	if mxhost == None:
		# A missing MX record is okay on the primary hostname because
		# the primary hostname's A record (the MX fallback) is... itself,
		# which is what we want the MX to be.
		if domain == env['PRIMARY_HOSTNAME']:
			output.print_ok("Domain's email is directed to this domain. [%s has no MX record, which is ok]" % (domain,))

		# And a missing MX record is okay on other domains if the A record
		# matches the A record of the PRIMARY_HOSTNAME. Actually this will
		# probably confuse DANE TLSA, but we'll let that slide for now.
		else:
			domain_a = query_dns(domain, "A", nxdomain=None)
			primary_a = query_dns(env['PRIMARY_HOSTNAME'], "A", nxdomain=None)
			if domain_a != None and domain_a == primary_a:
				output.print_ok("Domain's email is directed to this domain. [%s has no MX record but its A record is OK]" % (domain,))
			else:
				output.print_error("""This domain's DNS MX record is not set. It should be '%s'. Mail will not
					be delivered to this box. It may take several hours for public DNS to update after a
					change. This problem may result from other issues listed here.""" % (recommended_mx,))

	elif mxhost == env['PRIMARY_HOSTNAME']:
		good_news = "Domain's email is directed to this domain. [%s => %s]" % (domain, mx)
		if mx != recommended_mx:
			good_news += "  This configuration is non-standard.  The recommended configuration is '%s'." % (recommended_mx,)
		output.print_ok(good_news)
	else:
		output.print_error("""This domain's DNS MX record is incorrect. It is currently set to '%s' but should be '%s'. Mail will not
			be delivered to this box. It may take several hours for public DNS to update after a change. This problem may result from
			other issues listed here.""" % (mx, recommended_mx))

	# Check that the postmaster@ email address exists. Not required if the domain has a
	# catch-all address or domain alias.
	if "@" + domain not in dict(get_mail_aliases(env)):
		check_alias_exists("postmaster@" + domain, env, output)

	# Stop if the domain is listed in the Spamhaus Domain Block List.
	# The user might have chosen a domain that was previously in use by a spammer
	# and will not be able to reliably send mail.
	dbl = query_dns(domain+'.dbl.spamhaus.org', "A", nxdomain=None)
	if dbl is None:
		output.print_ok("Domain is not blacklisted by dbl.spamhaus.org.")
	else:
		output.print_error("""This domain is listed in the Spamhaus Domain Block List (code %s),
			which may prevent recipients from receiving your mail.
			See http://www.spamhaus.org/dbl/ and http://www.spamhaus.org/query/domain/%s.""" % (dbl, domain))

def check_web_domain(domain, env, output):
	# See if the domain's A record resolves to our PUBLIC_IP. This is already checked
	# for PRIMARY_HOSTNAME, for which it is required for mail specifically. For it and
	# other domains, it is required to access its website.
	if domain != env['PRIMARY_HOSTNAME']:
		ip = query_dns(domain, "A")
		if ip == env['PUBLIC_IP']:
			output.print_ok("Domain resolves to this box's IP address. [%s => %s]" % (domain, env['PUBLIC_IP']))
		else:
			output.print_error("""This domain should resolve to your box's IP address (%s) if you would like the box to serve
				webmail or a website on this domain. The domain currently resolves to %s in public DNS. It may take several hours for
				public DNS to update after a change. This problem may result from other issues listed here.""" % (env['PUBLIC_IP'], ip))

	
_apt_updates = None
def list_apt_updates(apt_update=True):
	# See if we have this information cached recently.
	# Keep the information for 8 hours.
	global _apt_updates
	if _apt_updates is not None and _apt_updates[0] > datetime.datetime.now() - datetime.timedelta(hours=8):
		return _apt_updates[1]

	# Run apt-get update to refresh package list. This should be running daily
	# anyway, so on the status checks page don't do this because it is slow.
	if apt_update:
		shell("check_call", ["/usr/bin/apt-get", "-qq", "update"])

	# Run apt-get upgrade in simulate mode to get a list of what
	# it would do.
	simulated_install = shell("check_output", ["/usr/bin/apt-get", "-qq", "-s", "upgrade"])
	pkgs = []
	for line in simulated_install.split('\n'):
		if line.strip() == "":
			continue
		if re.match(r'^Conf .*', line):
			 # remove these lines, not informative
			continue
		m = re.match(r'^Inst (.*) \[(.*)\] \((\S*)', line)
		if m:
			pkgs.append({ "package": m.group(1), "version": m.group(3), "current_version": m.group(2) })
		else:
			pkgs.append({ "package": "[" + line + "]", "version": "", "current_version": "" })

	# Cache for future requests.
	_apt_updates = (datetime.datetime.now(), pkgs)

	return pkgs


class ConsoleOutput:
	try:
		terminal_columns = int(shell('check_output', ['stty', 'size']).split()[1])
	except:
		terminal_columns = 76

	def add_heading(self, heading):
		print()
		print(heading)
		print("=" * len(heading))

	def print_ok(self, message):
		self.print_block(message, first_line="✓  ")

	def print_error(self, message):
		self.print_block(message, first_line="✖  ")

	def print_warning(self, message):
		self.print_block(message, first_line="?  ")

	def print_block(self, message, first_line="   "):
		print(first_line, end='')
		message = re.sub("\n\s*", " ", message)
		words = re.split("(\s+)", message)
		linelen = 0
		for w in words:
			if linelen + len(w) > self.terminal_columns-1-len(first_line):
				print()
				print("   ", end="")
				linelen = 0
			if linelen == 0 and w.strip() == "": continue
			print(w, end="")
			linelen += len(w)
		print()

	def print_line(self, message, monospace=False):
		for line in message.split("\n"):
			self.print_block(line)

class BufferedOutput:
	# Record all of the instance method calls so we can play them back later.
	def __init__(self):
		self.buf = []
	def __getattr__(self, attr):
		if attr not in ("add_heading", "print_ok", "print_error", "print_warning", "print_block", "print_line"):
			raise AttributeError
		# Return a function that just records the call & arguments to our buffer.
		def w(*args, **kwargs):
			self.buf.append((attr, args, kwargs))
		return w
	def playback(self, output):
		for attr, args, kwargs in self.buf:
			getattr(output, attr)(*args, **kwargs)


if __name__ == "__main__":
	import sys
	from utils import load_environment
	env = load_environment()
	if len(sys.argv) == 1:
		pool = multiprocessing.pool.Pool(processes=10)
		run_checks(env, ConsoleOutput(), pool)
	elif sys.argv[1] == "--check-primary-hostname":
		# See if the primary hostname appears resolvable and has a signed certificate.
		domain = env['PRIMARY_HOSTNAME']
		if query_dns(domain, "A") != env['PUBLIC_IP']:
			sys.exit(1)
		ssl_key, ssl_certificate, ssl_via = get_domain_ssl_files(domain, env)
		if not os.path.exists(ssl_certificate):
			sys.exit(1)
		cert_status, cert_status_details = check_certificate(domain, ssl_certificate, ssl_key)
		if cert_status != "OK":
			sys.exit(1)
		sys.exit(0)


