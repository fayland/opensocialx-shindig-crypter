package OpenSocialX::Shindig::Crypter::V11;

# ABSTRACT: Shindig 1.1 (OpenSocial Spec 0.9) Crypter

=pod

=head1 SYNOPSIS
 
    use OpenSocialX::Shindig::Crypter;
    
    my $crypter = OpenSocialX::Shindig::Crypter->new( {
        version => '1.1',
        cipher  => 'length16length16',
        hmac    => 'forhmac_sha1',
        iv      => 'anotherlength16k'
    } );

=head1 DESCRIPTION

Read L<OpenSocialX::Shindig::Crypter> for usage

=cut

use URI::Escape qw/uri_escape/;
use base 'OpenSocialX::Shindig::Crypter::Base';

my $OWNER_KEY = "o";
my $APP_KEY = "a";
my $VIEWER_KEY = "v";
my $DOMAIN_KEY = "d";
my $APPURL_KEY = "u";
my $MODULE_KEY = "m";
my $CONTAINER_KEY = "c";
sub create_token {
    my $self = shift;
    
    my $data = defined $_[0] && ref($_[0]) eq 'HASH' ? shift : { @_ };    
    my $token_data = {
        $OWNER_KEY  => $data->{owner},
        $APP_KEY    => $data->{app},
        $VIEWER_KEY => $data->{viewer},
        $DOMAIN_KEY => $data->{domain},
        $APPURL_KEY => $data->{app_url},
        $MODULE_KEY => $data->{module_id},
        $CONTAINER_KEY => $data->{container_id},
    };
    my $token = $self->wrap( $token_data );
    return uri_escape( $token );
}

1;