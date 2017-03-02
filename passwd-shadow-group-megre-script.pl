#!/usr/bin/perl

# use strict;
# use warnings;
use 5.010;
use File::Copy qw(copy);

open PASSWD, "<$ARGV[1]/etc/passwd" or die $!;
open SHADOW, "<$ARGV[1]/etc/shadow" or die $!;
open GROUP, "<$ARGV[1]/etc/group" or die $!;
open OPASSWD, "<$ARGV[0]/etc/passwd" or die $!;
open OSHADOW, "<$ARGV[0]/etc/shadow" or die $!;
open OGROUP, "<$ARGV[0]/etc/group" or die $!;

# Create backups on the receiver

copy "$ARGV[1]/etc/passwd", "$ARGV[1]/etc/passwd-receiver-orig" or die "Copy failed: $!";
copy "$ARGV[1]/etc/shadow", "$ARGV[1]/etc/shadow-receiver-orig" or die "Copy failed: $!";
copy "$ARGV[1]/etc/group", "$ARGV[1]/etc/group-receiver-orig" or die "Copy failed: $!";
copy "$ARGV[0]/etc/passwd", "$ARGV[1]/etc/passwd-sender-orig" or die "Copy failed: $!";
copy "$ARGV[0]/etc/shadow", "$ARGV[1]/etc/shadow-sender-orig" or die "Copy failed: $!";
copy "$ARGV[0]/etc/group", "$ARGV[1]/etc/group-sender-orig" or die "Copy failed: $!";

# Read this hosts /etc/passwd into memory
# nfsnobody:x:4294967294:4294967294:Anonymous NFS User:/var/lib/nfs:/dev/null
while ( <PASSWD> ) {
chomp;
my ($uid,$junkpass,$pruid,$pguid,$officename,$homedir,$shell) = split(/:/,$_,7);
$THISHOST{$uid}{'junkpass'} = $junkpass;
$THISHOST{$uid}{'pruid'} = $pruid;
$THISHOST{$uid}{'pguid'} = $pguid;
$THISHOST{$uid}{'officename'} = $officename;
$THISHOST{$uid}{'homedir'} = $homedir;
$THISHOST{$uid}{'shell'} = $shell;
}
close PASSWD;
# Read other machine's /etc/passwd into memory
while (<OPASSWD>) {
chomp;
my ($uid,$junkpass,$pruid,$pguid,$officename,$homedir,$shell) = split(/:/,$_,7);
$THATHOST{$uid}{'junkpass'} = $junkpass;
$THATHOST{$uid}{'pruid'} = $pruid;
$THATHOST{$uid}{'pguid'} = $pguid;
$THATHOST{$uid}{'officename'} = $officename;
$THATHOST{$uid}{'homedir'} = $homedir;
$THATHOST{$uid}{'shell'} = $shell;
}
close OPASSWD;
# Read this hosts /etc/shadow into memory
# aua:$1$6LzssYvL$Wqs94Dv/ZSkuGl0LXQpKb1:13392:0:99999:7:::
while (<SHADOW>) {
chomp;
my ($uid,$passstring,$rest) = split(/:/,$_,3);
$THISSHADOW{$uid}{'passstring'} = $passstring;
$THISSHADOW{$uid}{'rest'} = $rest;
}
close SHADOW;
# Read other machine's /etc/shadow into memory
while (<OSHADOW>) {
chomp;
my ($uid,$passstring,$rest) = split(/:/,$_,3);
$THATSHADOW{$uid}{'passstring'} = $passstring;
$THATSHADOW{$uid}{'rest'} = $rest;
}
close OSHADOW;
# Read this hosts /etc/group into memory
# daemon:x:2:
while ( <GROUP> ) {
chomp;
my ($group_name,$password,$gid,$user_list) = split(/:/,$_,4);
$THISGROUP{$group_name}{'password'} = $password;
$THISGROUP{$group_name}{'gid'} = $gid;
$THISGROUP{$group_name}{'user_list'} = $user_list;
}
close GROUP;
# Read other machine's /etc/group into memory
while (<OGROUP>) {
chomp;
my ($group_name,$password,$gid,$user_list) = split(/:/,$_,4);
$THATGROUP{$group_name}{'password'} = $password;
$THATGROUP{$group_name}{'gid'} = $gid;
$THATGROUP{$group_name}{'user_list'} = $user_list;
}
close OGROUP;
# Check for missing accounts
foreach $account (sort keys %THATHOST) {
if (!(defined($THISHOST{$account}))) {
print "Missing $account\n";
$passwdbuf = $passwdbuf . "$account:$THATHOST{$account}{junkpass}:$THATHOST{$account}{pruid}:$THATHOST{$account}{pguid}:$THATHOST{$account}{officename}:$THATHOST{$account}{homedir}:$THATHOST{$account}{shell}\n";
$shadowbuf = $shadowbuf . "$account:$THATSHADOW{$account}{passstring}:$THATSHADOW{$account}{rest}\n";
} else {
print "$account: $THISHOST{$account}{pruid} = $THATHOST{$account}{pruid}\n";
}
if ((defined($THISHOST{$account})) && ($THISHOST{$account}{pruid} ne $THATHOST{$account}{pruid})) {
$uiderrors = $uiderrors . "$account: Source: $THATHOST{$account}{pruid} Receiver: $THISHOST{$account}{pruid}\n";

  if ( length $uidrsync > 0 ) {
  $uidrsync = $uidrsync . ",$THATHOST{$account}{pruid}:$THISHOST{$account}{pruid}";
  } else {
  $uidrsync = "--usermap=" . $THATHOST{$account}{pruid} . ":" . $THISHOST{$account}{pruid};
  }

}
if ((defined($THISHOST{$account})) && ($THISHOST{$account}{pguid} ne $THATHOST{$account}{pguid})) {
$usergiderrors = $usergiderrors . "$account: Source: $THATHOST{$account}{pguid} Receiver: $THISHOST{$account}{pguid}\n";
}
if ((defined($THISSHADOW{$account})) && ($THISSHADOW{$account}{passstring} ne $THATSHADOW{$account}{passstring})) {
$passworderrors = $passworderrors . "$account: Source: $THATSHADOW{$account}{passstring} Receiver: $THISSHADOW{$account}{passstring}\n";

# A code which replaces the password hash in /etc/shadow file on the receiver host
my $SHADOW = "$ARGV[1]/etc/shadow";
my $SHADOWTEMP = "$ARGV[1]/etc/shadow-temp";

my $oldpassword = quotemeta($THISSHADOW{$account}{passstring});
my $newpassword = quotemeta($THATSHADOW{$account}{passstring});

chmod 0600, $SHADOW or die "Couldn't change the permission to $SHADOW: $!";
open my $rf, '<', $SHADOW or die "Cannot open $SHADOW for reading.";
open my $wf, '>'. $SHADOWTEMP or die "Cannot open $SHADOWTEMP for writing.";

while ( <$rf> ) {
    if (/$account/ and /$oldpassword/) {
        s/$oldpassword/$newpassword/ ;
    }
    print $wf $_;
}

close $rf;
close $wf;

unlink $SHADOW;
rename $SHADOWTEMP, $SHADOW;
chmod 0000, $SHADOW or die "Couldn't change the permission to $SHADOW: $!";

}
}
# Check for missing groups
foreach $group (sort keys %THATGROUP) {
if (!(defined($THISGROUP{$group}))) {
print "Missing $group\n";
$groupbuf = $groupbuf . "$group:$THATGROUP{$group}{password}:$THATGROUP{$group}{gid}:$THATGROUP{$group}{user_list}\n";
} else {
print "$group: $THISGROUP{$group}{gid} = $THATGROUP{$group}{gid}\n";
}
if ((defined($THISGROUP{$group})) && ($THISGROUP{$group}{gid} ne $THATGROUP{$group}{gid})) {
$giderrors = $giderrors . "$group: Source: $THATGROUP{$group}{gid} Receiver: $THISGROUP{$group}{gid}\n";

  if ( length $gidrsync > 0 ) {
  $gidrsync = $gidrsync . ",$THATGROUP{$group}{gid}:$THISGROUP{$group}{gid}";
  } else {
  $gidrsync = "--groupmap=" . $THATGROUP{$group}{gid} . ":" . $THISGROUP{$group}{gid};
  }

}
if ((defined($THISGROUP{$group})) && ($THISGROUP{$group}{user_list} ne $THATGROUP{$group}{user_list})) {
$userlisterrors = $userlisterrors . "$group: Source: $THATGROUP{$group}{user_list} Receiver: $THISGROUP{$group}{user_list}\n";
}
if ((defined($THISGROUP{$group})) && ($THISGROUP{$group}{password} ne $THATGROUP{$group}{password})) {
$grouppassworderrors = $grouppassworderrors . "$group: Source: $THATGROUP{$group}{password} Receiver: $THISGROUP{$group}{password}\n";
}
}

# Output missing accounts for /etc/passwd
print "------------------\n";
print "Add to /etc/passwd\n";
print "$passwdbuf\n";

# A code which adds missing accounts to /etc/passwd on the receiver host
my $PASSWD = "$ARGV[1]/etc/passwd";
# my $PASSWD = 'passwd-temp';

open my $wf, '>>'. $PASSWD or die "Cannot open $PASSWD for writing.";

print $wf $passwdbuf;

close $wf;

# Output missing accounts for /etc/shadow
print "------------------\n";
print "Add to /etc/shadow\n";
print "$shadowbuf\n";

# A code which adds missing accounts to /etc/shadow on the receiver host
my $SHADOW = "$ARGV[1]/etc/shadow";
# my $SHADOW = 'shadow-temp';

chmod 0600, $SHADOW or die "Couldn't change the permission to $SHADOW: $!";
open my $wf, '>>'. $SHADOW or die "Cannot open $SHADOW for writing.";

print $wf $shadowbuf;

close $wf;
chmod 0000, $SHADOW or die "Couldn't change the permission to $SHADOW: $!";

# UID Mis-matches
print "------------------\n";
print "UID Mis-matches\n";
print "$uiderrors";
print "rsync params: $uidrsync\n\n";

# GID Mis-matches
print "------------------\n";
print "User GID Mis-matches\n";
print "$usergiderrors\n";

# Password Mis-matches
print "------------------\n";
print "Password Mis-matches\n";
print "$passworderrors\n";

# Output missing groups for /etc/group
print "------------------\n";
print "Add to /etc/group\n";
print "$groupbuf\n";

# A code which adds missing groups to /etc/group on the receiver host
my $GROUP = "$ARGV[1]/etc/group";
# my $GROUP = 'group-temp';

open my $wf, '>>'. $GROUP or die "Cannot open $GROUP for writing.";

print $wf $groupbuf;

close $wf;

# GID Mis-matches
print "------------------\n";
print "GID Mis-matches\n";
print "$giderrors";
print "rsync params: $gidrsync\n\n";

# user_list Mis-matches
print "------------------\n";
print "user_list Mis-matches\n";
print "$userlisterrors\n";

# Group password Mis-matches
print "------------------\n";
print "Group password Mis-matches\n";
print "$grouppassworderrors\n";

# Resulting rsync string
print "------------------\n";
print "Resulting rsync string:\n";
print "rsync -aSHPvz --numeric-ids $uidrsync $gidrsync --exclude-from=\"exclude.txt\" $ARGV[0]/ $ARGV[1]/\n";
