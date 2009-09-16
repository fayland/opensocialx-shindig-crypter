package OpenSocialX::Shindig::Crypter;

# ABSTRACT: Shindig Crypter

use URI::Escape qw/uri_escape uri_unescape/;
use MIME::Base64 qw/decode_base64 encode_base64/;
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
    my $token = $crypter->create_token( {
        owner    => $owner_id,
        viewer   => $viewer_id,
        app      => $app_id,
        app_url  => $app_url,
        domain   => $domain,
        module_id => $module_id
    } );

=head1 DESCRIPTION



=cut

# Key used for time stamp (in seconds) of data
my $TIMESTAMP_KEY = 't';

# allow three minutes for clock skew
my $CLOCK_SKEW_ALLOWANCE = 180;

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

sub wrap {
    my ( $self, $in ) = @_;

    my $encoded = _serializeAndTimestamp($in);
    my $cipher = Crypt::CBC->new( {
        'key' => $self->{cipher},
        'cipher'=> 'Rijndael',
        'iv' => $self->{iv},
        'literal_key' => 1,
        'padding' => 'null',
        'header' => 'none',
        keysize => 128/8,
    } );
    my $cipherText = $cipher->encrypt($encoded);
    my $hmac = Digest::SHA::hmac_sha1($cipherText, $self->{hmac});
    print STDERR "hmac length " . length($hmac) . "ciper length " . length($cipherText) . "\n";
    
    my $b64 = encode_base64($cipherText . $hmac);
    while (length($b64) % 4) {
        $b64 .= '=';
    }
    return $b64;
}

sub _serializeAndTimestamp {
    my ( $in ) = @_;
    
    my $encoded;
    foreach my $key (keys %$in) {
        $encoded .= uri_escape($key) . "=" . uri_escape($in->{$key}) . "&";
    }
    $encoded .= $TIMESTAMP_KEY . "=" . time();
    return $encoded;
}

sub unwrap {
    my ( $self, $in, $max_age ) = @_;

    my $bin = decode_base64($in);
    print STDERR "length is " . length($bin) . "\n";
    my $cipherText = substr($bin, 0, length($bin) - 20);
    my $hmac = substr($bin, length($bin) - 20, 20);
    
    # verify
    my $v_hmac = Digest::SHA::hmac_sha1($cipherText, $self->{hmac});
    print STDERR "\n$v_hmac\n$hmac\n";
    if ( $v_hmac ne $hmac ) {
        die 'HMAC verification failure';
    }
    my $cipher = Crypt::CBC->new( {
        'key' => $self->{cipher},
        'cipher'=> 'Rijndael',
        'iv' => $self->{iv},
        'literal_key' => 1,
        'padding' => 'null',
        'header' => 'none',
        keysize => 128/8,
    } );
    my $plain = $cipher->decrypt($cipherText);
    my $out = $self->deserialize($plain);
    
    $self->checkTimestamp($out, $max_age);
    
    return $out;
}

sub deserialize {
    my ( $self, $plain ) = @_;

    my $h;
    my @items = split(/[\&\=]/, $plain);
    my $i;
    for ($i = 0; $i < scalar(@items);) {
      my $key = uri_unescape($items[$i ++]);
      my $value = uri_unescape($items[$i ++]);
      $h->{$key} = $value;
    }
    return $h;
}

sub checkTimestamp {
    my ( $self, $out, $max_age ) = @_;

    my $minTime = $out->{$TIMESTAMP_KEY} - $CLOCK_SKEW_ALLOWANCE;
    my $maxTime = $out->{$TIMESTAMP_KEY} + $max_age + $CLOCK_SKEW_ALLOWANCE;
    my $now = time();
    if (! ($minTime < $now && $now < $maxTime)) {
      die "Security token expired";
    }
}

my $OWNER_KEY = "o";
my $APP_KEY = "a";
my $VIEWER_KEY = "v";
my $DOMAIN_KEY = "d";
my $APPURL_KEY = "u";
my $MODULE_KEY = "m";
sub create_token {
    my ( $self, $data ) = @_;
    
    my $token_data = {
        $OWNER_KEY  => $data->{owner},
        $APP_KEY    => $data->{app},
        $VIEWER_KEY => $data->{viewer},
        $DOMAIN_KEY => $data->{domain},
        $APPURL_KEY => $data->{app_url},
        $MODULE_KEY => $data->{module_id},
    };
    my $token = $self->wrap( $token_data );
    return uri_escape( $token );
}

1;