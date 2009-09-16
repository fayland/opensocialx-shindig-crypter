package OpenSocialX::Shindig::Crypter;

# ABSTRACT: Shindig Crypter

use URI::Escape;
use MIME::Base64;
use Crypt::CBC;
use Digest::SHA;

=pod

=head1 SYNOPSIS
 
    use OpenSocialX::Shindig::Crypter;
    
    my $crypter = OpenSocialX::Shindig::Crypter->new( {
        cipher => 'length16length16',
        hmac   => 'forhmac_sha1',
        iv     => 'anotherlength16k'
    } );

=head1 DESCRIPTION



=cut

sub new {
    my $class = shift;

    my $cfg = defined $_[0] && ref($_[0]) eq 'HASH' ? shift : { @_ };
    
    # validate
    $cfg->{cipher} or die 'cipher key is required';
    $cfg->{hmac}   or die 'hmac key is required';
    $cfg->{iv}     or die 'iv key is required';
    
    ( length($cfg->{cipher}) == 16 ) or die 'cipher key must be 16 chars';
    ( length($cfg->{iv}) == 16 )     or die 'iv key must be 16 chars';

    return bless $cfg, $class;
}

1;