#!/usr/bin/perl -w
 use IO::Prompt;
 use File::Copy;
 use Cwd;
########################################################################
#
# Securing a server based on the excellent Ubuntu security writeup here:
# 
#    http://www.thefanclub.co.za/how-to/how-secure-ubuntu-1204-lts-server-part-1-basics
# 
# 
########################################################################

my $cwd = getcwd();
my $log = "$cwd/server-setup.log";

# GLOBAL HELPERS
sub trim {
   return $_[0] =~ s/^\s+|\s+$//rg;
}

sub run {
   my $logline = "@_";
   open my $touch, '>>', $log or die $!;
   close $touch;
   system(@_) == 0
      or die "system @_ failed: $?";
   open my $out, '>>', $log or die $!;
   print $out "$logline\n";
   close $out;
   print STDOUT "\n";
}

# modify_config (path, newline delimited values)
sub modify_config {
   local $file = $_[0];
   local $file_copy = $file . "_copy";
   local $num_vals = scalar (@_);
   --$num_vals;
   local @to_update = splice (@_, 1, $num_vals);
   local @to_append = @to_update;
   
   open local $log_out, '>>', $log or die $!;
   print $log_out "\n\n--------------------------------\n";
   print $log_out "       $file";
   print $log_out "\n--------------------------------\n\n";

   open local $config, '<', "$file" or die "Can't open $file: $!";
   open local $copy, '>', "$file_copy" or die "Can't create $file_copy: $!";
   LINE: while (my $line = <$config>) {
      chomp ($line);
      if (length ($line) == 0) {
         print $copy "\n";
         next LINE;
      }
      
      local $modified = 0;
      local $index = 0;
      foreach my $val (@to_update) {
         local $delim = " ";
         local $key = "";
         if (index ($val, "-->") != -1) {
            $delim = "-->";
         } elsif (index ($val, "=") != -1) {
            $delim = "=";
         }
         $key = trim ((split ($delim, $val))[0]);
         if (index ($line, $key) == 0) {            
            # check for function calls
            if ($delim eq " " || $delim eq "=") {
               local $add_func = "^add\(.+\)";
               local $to_add = trim ((split ($delim, $val))[1]);
               if ($to_add =~ /$add_func/) {
                  $to_add = substr ($to_add, 4, length($to_add) - 5);                  
                  local $existing_delim = " ";
                  if (index ($line, "=") != -1) {
		     $existing_delim = "=";
		  }
                  local $existing_val = trim ((split ($existing_delim, $line))[1]);
                  if (length (trim ($existing_val)) != 0 && substr($existing_val, length($existing_val) - 1, 1) ne ",") {
                     $existing_val .= ",";
                  }
                  $val = "$key$delim$existing_val$to_add";
               }
            } elsif ($delim eq "-->") {
               $val = trim ((split ("-->", $val))[1]);
            }
            $modified = "$val";
            print $copy "$val\n";
            $to_append[$index] = "";
         }
         $index++;
      }
      if ($modified) {
         if ($line ne $modified) {
            print $log_out "MODIFIED: $line ===> $modified";
            print $log_out "\n";
         }
      } else {
         print $copy "$line\n";
      }
   }
   close $config;
   foreach my $val (@to_append) {
      if ($val) {
         local $delim = " ";
         if (index ($val, "-->") != -1) {
            $val = trim ((split ("-->", $val))[1]);
            $delim = "-->";
         } elsif (index ($val, "=") != -1) {
            $delim = "=";
         }
         # check for function calls
	 if ($delim eq " " || $delim eq "=") {
	    local $add_func = "^add\(.+\)";
	    local $to_add = trim ((split ($delim, $val))[1]);
	    if ($to_add =~ /$add_func/) {
	       $key = trim ((split ($delim, $val))[0]);
	       $to_add = substr ($to_add, 4, scalar($to_add) - 5);
	       $val = "$key$delim$to_add";
	    }
         }
         print $log_out "APPENDED: $val";
         print $log_out "\n";
         print $copy "$val\n";
      }
   }
   close $copy;
   close $log_out;
   move ($file_copy, $file) or die "Couldn't modify $file: $!";
}

# MAIN
while (prompt "\nServer admin email? [me\@example.com]: ", -until => qr/[^@\.]+@[^\.]+\.[^\.]+/) {
   print STDOUT "Invalid email.  Retry.\n";
}
my $email = trim ($_);

while (prompt "\nWhat domain name are you using the server for [example.com]? ", -while => qr/^$/) {}
local $site = trim ($_);
if (index ($site, 'www.') == 0) {
   $site = substr ($site, 4);
}

# change root password   
print STDOUT "\nWe'll begin securing the server by changing the root password\n";
run ("passwd");

# create new user
print STDOUT "Next we need to create a new user to login since we'll no longer be using root\n";
while (prompt "\nWhat user name would you like to create? ", -while => qr/^$/) {}
my $user = trim ($_);

my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell) = getpwnam ($user);
if (!$name && !$passwd && !$uid && !$gid && !$quota && !$comment && !$gcos && !$dir && !$shell) {
   run ("adduser", $user);
}

# add new user to sudoers
modify_config ("/etc/sudoers",
                "$user    ALL=(ALL:ALL) ALL");

# protect su by limiting access only to admin group.
run ("groupadd", "-f", "admin");
run ("usermod", "-a", "-G", "admin", $user);
run ("dpkg-statoverride", "--force", "--update", "--add", "root", "admin", "4750", "/bin/su");

# harden network with sysctl settings
modify_config ("/etc/sysctl.conf",
                # IP Spoofing protection
                "net.ipv4.conf.all.rp_filter = 1",
                "net.ipv4.conf.default.rp_filter = 1",

                # Ignore ICMP broadcast requests
                "net.ipv4.icmp_echo_ignore_broadcasts = 1",
                
                # Disable source packet routing
                "net.ipv4.conf.all.accept_source_route = 0",
                "net.ipv6.conf.all.accept_source_route = 0",
                "net.ipv4.conf.default.accept_source_route = 0",
                "net.ipv6.conf.default.accept_source_route = 0",
                
                # Ignore send redirects
                "net.ipv4.conf.all.send_redirects = 0",
                "net.ipv4.conf.default.send_redirects = 0",
                
                # Block SYN attacks
                "net.ipv4.tcp_syncookies = 1",
                "net.ipv4.tcp_max_syn_backlog = 2048",
                "net.ipv4.tcp_synack_retries = 2",
                "net.ipv4.tcp_syn_retries = 5",
                
                # Log Martians
                "net.ipv4.conf.all.log_martians = 1",
                "net.ipv4.icmp_ignore_bogus_error_responses = 1",
                
                # Ignore ICMP redirects
                "net.ipv4.conf.all.accept_redirects = 0",
                "net.ipv6.conf.all.accept_redirects = 0",
                "net.ipv4.conf.default.accept_redirects = 0",
                "net.ipv6.conf.default.accept_redirects = 0",
                
                # Ignore Directed pings
                "net.ipv4.icmp_echo_ignore_all = 1");
run ("sysctl", "-p");

# disable open DNS recursion and Remove Version info - BIND DNS Server
if (-e "/etc/bind/named.conf.options") {
   modify_config ("/etc/bind/named.conf.options",
                   "recursion no;",
                   "version \"Not Disclosed\";");
   run ("/etc/init.d/bind9", "restart");
}

# Prevent IP Spoofing
modify_config ("/etc/host.conf",
                "order bind,hosts",
                "nospoof on");

# harden PHP
if (-e "/etc/php5/apache2/php.ini") {
   modify_config("/etc/php5/apache2/php.ini",
                  "disable_functions = add(exec,system,shell_exec,passthru)",
                  "register_globals = Off",
                  "expose_php = Off",
                  "display_errors = Off",
                  "track_errors = Off",
                  "html_errors = Off",
                  "magic_quotes_gpc = Off");
} else {
   print STDOUT "\n\nWARNING ----- /etc/php5/apache2/php.ini file not found.  Must secure PHP manually.\n\n";
   print STDOUT "Add or edit the following lines an save :\n";
   print STDOUT "\tdisable_functions = exec,system,shell_exec,passthru\n" .
                "\tregister_globals = Off\n" .
                "\texpose_php = Off\n" .
                "\tdisplay_errors = Off\n" .
                "\ttrack_errors = Off\n" .
                "\thtml_errors = Off\n" .
                "\tmagic_quotes_gpc = Off\n\n";
}

# configure SSH
modify_config ("/etc/ssh/sshd_config",
                "PermitRootLogin no",
                "DebianBanner no",
                "Protocol 2",
                "UseDNS no",
                "AllowUsers $user");

# prevent Apache info leakage
modify_config ("/etc/apache2/conf.d/security",
                "ServerTokens Prod",
                "ServerSignature Off",
                "TraceEnable Off",
                "Header set ETag-->Header unset ETag",
                "FileETag None");
run ("a2enmod", "headers");

# install apache2 mod_security
run ("apt-get", "install", "-y", "libxml2", "libxml2-dev", "libxml2-utils");
run ("apt-get", "install", "-y", "libaprutil1", "libaprutil1-dev");
#run ("ln", "-s", "/usr/lib/x86_64-linux-gnu/libxml2.so.2", "/usr/lib/libxml2.so.2");
run ("apt-get", "install", "-y", "libapache-mod-security");
move ("/etc/modsecurity/modsecurity.conf-recommended", "/etc/modsecurity/modsecurity.conf");
modify_config ("/etc/modsecurity/modsecurity.conf",
                "SecRuleEngine On",
                
                # increase upload limit to 16MB
                "SecRequestBodyLimit 16384000",
                "SecRequestBodyInMemoryLimit 16384000"
                );
run ("wget", "-O", "SpiderLabs-owasp-modsecurity-crs.tar.gz", "https://github.com/SpiderLabs/owasp-modsecurity-crs/tarball/master");
run ("tar", "-zxvf", "SpiderLabs-owasp-modsecurity-crs.tar.gz");
my @glob = glob ("SpiderLabs-owasp-modsecurity-crs-*/*");
foreach my $filename (@glob) {
   run ("cp", "-R", $filename, "/etc/modsecurity/");
}
run ("rm", "SpiderLabs-owasp-modsecurity-crs.tar.gz");
@glob = glob ("SpiderLabs-owasp-modsecurity-crs-*");
run ("rm", "-R", $glob[0]);

@glob = map m|([^/]+)$|, </etc/modsecurity/base_rules/*>;
foreach my $file (@glob) {
   run ("ln", "-sf", "/etc/modsecurity/base_rules/$file", "/etc/modsecurity/activated_rules/$file");
}

@glob = map m|([^/]+)$|, </etc/modsecurity/optional_rules/*>;
foreach my $file (@glob) {
   run ("ln", "-sf", "/etc/modsecurity/optional_rules/$file", "/etc/modsecurity/activated_rules/$file");
}

move ("/etc/modsecurity/modsecurity_crs_10_setup.conf.example", "/etc/modsecurity/modsecurity_crs_10_setup.conf");
modify_config ("/etc/apache2/mods-available/mod-security.conf",
                "</IfModule>-->Include \"/etc/modsecurity/activated_rules/*.conf\"\n</IfModule>");
run ("a2enmod", "mod-security");

# install apache2 mod_evasive
run ("apt-get", "install", "-y", "libapache2-mod-evasive");
run ("mkdir", "/var/log/mod_evasive");
run ("chown", "www-data:www-data", "/var/log/mod_evasive/");
open my $mod_evasive, '>', "mod_evasive.conf" or die "Can't create mod_evasive.conf file: $!";
print $mod_evasive "<ifmodule mod_evasive20.c>\n" .
                      "\tDOSHashTableSize 3097\n" .
                      "\tDOSPageCount  2\n" .
                      "\tDOSSiteCount  50\n" .
                      "\tDOSPageInterval 1\n" .
                      "\tDOSSiteInterval  1\n" .
                      "\tDOSBlockingPeriod  10\n" .
                      "\tDOSLogDir   /var/log/mod_evasive\n" .
                      "\tDOSEmailNotify  $email\n" .
                      "\tDOSWhitelist   127.0.0.1\n" .
                   "</ifmodule>";
close $mod_evasive;
move ("./mod_evasive.conf", "/etc/apache2/mods-available/mod-evasive.conf");
run ("ln", "-sf", "/etc/alternatives/mail /bin/mail/");
run ("a2enmod", "mod-evasive");

# finally activate new modules and restart apache
run ("service", "apache2", "reload");
run ("service", "apache2", "restart");

# install ufw
run ("apt-get", "install", "-y", "ufw");
run ("ufw", "enable");
run ("ufw", "allow", "ssh");
run ("ufw", "allow", "http");
run ("ufw", "allow", "https");
run ("ufw", "status", "verbose");

# install DenyHosts
run ("apt-get", "install", "-y", "denyhosts");
modify_config ("/etc/denyhosts.conf",
                "ADMIN_EMAIL = $email",
                "SMTP_FROM = DenyHosts nobody@$site");

# install Fail2ban
run ("apt-get", "install", "-y", "fail2ban");
open my $fail2ban_jail, '<', "/etc/fail2ban/jail.conf" or die "Can't open jail.conf file: $!";
open my $fail2ban_jail_copy, '>', "/etc/fail2ban/jail.conf_copy" or die "Can't create jail.conf temporary file: $!";
my $found_ssh_section = 0;
while (my $line = <$fail2ban_jail>) {
   if (index ($line, "[ssh]") == 0) {
      $found_ssh_section = 1;
      print $fail2ban_jail_copy $line;
   } elsif ($found_ssh_section) {
      if (index ($line, "enabled") == 0) {
         print $fail2ban_jail_copy "enabled  = true";
      } else {
         print $fail2ban_jail_copy $line;
      }
   } else {
      print $fail2ban_jail_copy $line;
   }
}
close $fail2ban_jail;
close $fail2ban_jail_copy;
move ("/etc/fail2ban/jail.conf_copy", "/etc/fail2ban/jail.conf");

run ("/etc/init.d/fail2ban", "restart");
run ("fail2ban-client", "status");

# install LogWatch
run ("apt-get", "install", "-y", "logwatch", "libdate-manip-perl");

# setup LogWatch cron job to send an email summary every 7 days
my $wants_email = prompt ("Would you like to receive LogWatch report email every 7 days? [y/n]: ", -ynd => "y");
if ($wants_email) {
   mkdir "/var/spool/cron/crontabs/$user";
   open my $log_watch_cron, '>', "/var/spool/cron/crontabs/$user/logwatch.pl" or die "Can't create LogWatch cron job: $!";
   print $log_watch_cron "logwatch --mailto $email --output mail --format html --range 'between -7 days and today'\n";
   close $log_watch_cron;
   # send email every Monday
   run ("crontab", "-e", "0", "0", "*", "*", "1", "/var/spool/cron/crontabs/$user/logwatch.pl");
}

# install Apparmor
run ("apt-get", "install", "-y", "apparmor", "apparmor-profiles");
run ("apparmor", "status");

# install Tiger
run ("apt-get", "install", "-y", "tiger");
run ("tiger");

# secure shared memory (requires reboot)
modify_config ("/etc/fstab",
                "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0\n");

# install PSAD
run ("apt-get", "install", "-y", "psad");
modify_config ("/etc/psad/psad.conf",
                "EMAIL_ADDRESSES             $email;",
                "HOSTNAME                    $site;",
                "ENABLE_AUTO_IDS             Y;",
                "ENABLE_AUTO_IDS_EMAILS      Y;"
                );
run ("iptables", "-A", "INPUT", "-j", "LOG");
run ("iptables", "-A", "FORWARD", "-j", "LOG");
run ("ip6tables", "-A", "INPUT", "-j", "LOG");
run ("ip6tables", "-A", "FORWARD", "-j", "LOG");
run ("psad", "-R");
run ("psad", "--sig-update");
run ("psad", "-H");
run ("psad", "--Status");

# scan open ports with Nmap
run ("apt-get", "install", "-y", "nmap");
print STDOUT "\n\n";
print STDOUT "Scanning your system for open ports using Nmap tool...\n\n";
run ("nmap", "-v", "-sT", "localhost");
print STDOUT "\n\n";
print STDOUT "SYN scanning your system for vulnerabilities using Nmap tool...\n\n";
run ("nmap", "-v", "-sS", "localhost");

# check system for rootkits with RKHunter and CHKRootKit
run ("apt-get", "install", "-y", "rkhunter", "chkrootkit");
print STDOUT "\n\n";
print STDOUT "Checking your system for rootkits using CHKRootKit...\n\n";
run ("chkrootkit");
print STDOUT "\n\n";
print STDOUT "Checking your system for rootkits using RKHunter...\n\n";
run ("rkhunter", "--update");
run ("rkhunter", "--propupd");
run ("rkhunter", "--check");

print STDOUT "Preparing to reboot server.  Your session is about to be lost.\n";
print STDOUT "Again, we've secured the server by disallowing root user login.\n";
print STDOUT "Use $user account to log back in.\n\n";

print STDOUT "\n\nServer setup completed successfully.\n\n";

my $reboot = prompt ("Reboot now? [y/n]: ", -ynd => "y");
if ($reboot) {
   run ("reboot");
} else {
   print STDOUT "\n\nWARNING ----- You will need to reboot for the changes to take affect.\n";
}
