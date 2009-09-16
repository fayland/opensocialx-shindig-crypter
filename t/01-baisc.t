#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 3;

use OpenSocialX::Shindig::Crypter;

my $crypter = OpenSocialX::Shindig::Crypter->new( {
    cipher => 'length16length16',
    hmac   => 'forhmac_sha1',
    iv     => 'anotherlength16k'
} );

my $hash = {
    a => 1,
    c => 3,
    o => 5
};

my $encrypted  = $crypter->wrap($hash);
sleep 1;
my $decrypted = $crypter->unwrap($encrypted, 3600);

is $decrypted->{a}, $hash->{a};
is $decrypted->{c}, $hash->{c};
is $decrypted->{o}, $hash->{o};