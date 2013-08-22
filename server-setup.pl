#!/usr/bin/perl -w
 use IO::Prompt;

print STDOUT "We'll begin securing the server by changing the root password\n";
system(("passwd")) == 0
   or die "system passwd failed: $?";

print STDOUT "Next we need to create a new user to log in since we'll no longer be using root\n";
my $user = prompt ("What user name would you like to use?");
system(("adduser", $user)) == 0
   or die "system adduser $user failed: $?";

