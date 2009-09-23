package OpenSocialX::Shindig::Crypter;

# ABSTRACT: OpenSocial Shindig Crypter

=pod

=head1 SYNOPSIS
 
    use OpenSocialX::Shindig::Crypter;
    
    my $crypter = OpenSocialX::Shindig::Crypter->new( {
        version => '1.0',
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

Apache Shindig L<http://incubator.apache.org/shindig/> is an OpenSocial container and helps you to start hosting OpenSocial apps quickly by providing the code to render gadgets, proxy requests, and handle REST and RPC requests.

From the article L<http://www.chabotc.com/generic/using-shindig-in-a-non-php-or-java-envirionment/>, we know that we can do 'Application' things in Perl. basically the stuff will be

=over 4

=item *

use Perl L<OpenSocialX::Shindig::Crypter> (this module) to create B<st=> encrypted token through C<create_token>

=item *

the php C<BasicBlobCrypter.php> will unwrap the token and validate it. The file is in the C<php> dir of this .tar.gz or you can download it from L<http://github.com/fayland/opensocialx-shindig-crypter/raw/master/php/BasicBlobCrypter.php>

you can copy it to the dir of C<extension_class_paths> defined in shindig/config/container.php, it will override the default C<BasicBlobCrypter.php> provided by shindig.

and the last thing is to defined the same keys in shindig/config/container.php like:

  'token_cipher_key' => 'length16length16',
  'token_hmac_key' => 'forhmac_sha1',
  'token_iv_key'   => 'anotherlength16k',

remember that C<token_iv_key> is new

=back

=head2 METHODS

=over 4

=item * new

    my $crypter = OpenSocialX::Shindig::Crypter->new( {
        version => '1.0',
        cipher => 'length16length16',
        hmac   => 'forhmac_sha1',
        iv     => 'anotherlength16k'
    } );

C<cipher> and C<iv> must be 16 chars.

note version => '1.0' (by default, it will be changed once Shindig 1.1 release) means Shindig 1.0, version => '1.1' means Shindig 1.1

=item * create_token

    my $token = $crypter->create_token( {
        owner    => $owner_id,
        viewer   => $viewer_id,
        app      => $app_id,
        app_url  => $app_url,
        domain   => $domain,
        module_id => $module_id
    } );

if you don't know what C<module_id> is, you can leave it alone.

In Shindig 1.1, there is a new key named 'container_id':

    my $token = $crypter->create_token( {
        owner    => $owner_id,
        viewer   => $viewer_id,
        app      => $app_id,
        app_url  => $app_url,
        domain   => $domain,
        module_id => $module_id,
        container_id => $container_id
    } );

=item * wrap

    my $encrypted  = $crypter->wrap({
        a => 1,
        c => 3,
        o => 5
    } );

encrypt the hash by L<Crypt::Rijndael> and L<Digest::SHA> and encode_base64 it

=item * unwrap

    my $hash = $crypter->unwrap($encrypted);

decrypt the above data

=item * deserialize

=item * checkTimestamp

=item * _serializeAndTimestamp

=cut

sub new {
    my $class = shift;

    my $cfg = defined $_[0] && ref($_[0]) eq 'HASH' ? shift : { @_ };
    
    my $version = $cfg->{version} || '1.0';
    if ( $version eq '1.0' or $version eq '0.8' or $version eq '0.8.1' ) {
        require OpenSocialX::Shindig::Crypter::V10;
        return OpenSocialX::Shindig::Crypter::V10->new($cfg);
    } elsif ( $version eq '1.1' or $version eq '0.9' ) {
        require OpenSocialX::Shindig::Crypter::V11;
        return OpenSocialX::Shindig::Crypter::V11->new($cfg);
    } else {
        die 'version must be 1.0 or 1.1';
    }
}

1;