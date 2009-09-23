package OpenSocialX::Shindig::Crypter::Base;

# ABSTRACT: Shindig 1.0 (OpenSocial Spec 0.8.1) Crypter

use URI::Escape qw/uri_escape uri_unescape/;
use MIME::Base64 qw/decode_base64 encode_base64/;
use Crypt::CBC;
use Digest::SHA;

=pod

=head1 SYNOPSIS
 
    package OpenSocialX::Shindig::Crypter::V10;
    use base 'OpenSocialX::Shindig::Crypter::Base';

=head1 DESCRIPTION

Read L<OpenSocialX::Shindig::Crypter> for usage

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
    my $b64 = encode_base64($cipherText . $hmac);
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
    my $cipherText = substr($bin, 0, -20);
    my $hmac = substr($bin, length($cipherText));
    
    # verify
    my $v_hmac = Digest::SHA::hmac_sha1($cipherText, $self->{hmac});
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

1;