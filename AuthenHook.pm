package Apache::AuthenHook;

use 5.008;

use DynaLoader ();

use Apache2::Module ();    # add()
use Apache2::CmdParms ();  # $parms->info

use Apache2::Const -compile => qw(OK DECLINE_CMD OR_AUTHCFG ITERATE);

use strict;

our @ISA = qw(DynaLoader);
our $VERSION = '2.00_04';

__PACKAGE__->bootstrap($VERSION);

my @directives = (
  { name         => 'AuthDigestProvider',
    errmsg       => 'specify the auth providers for a directory or location',
    args_how     => Apache2::Const::ITERATE,
    req_override => Apache2::Const::OR_AUTHCFG,
    cmd_data     => 'digest' },

  { name         => 'AuthBasicProvider',
    errmsg       => 'specify the auth providers for a directory or location',
    args_how     => Apache2::Const::ITERATE,
    req_override => Apache2::Const::OR_AUTHCFG,
    func         => 'AuthDigestProvider',
    cmd_data     => 'basic' },
);

Apache2::Module::add(__PACKAGE__, \@directives);

sub AuthDigestProvider {
  my ($cfg, $parms, $args) = @_;

  my @providers = split ' ', $args;

  foreach my $provider (@providers) {

    if ($provider =~ m/::/) {
      # if the provider looks like a Perl handler...

      # save the config for later
      push @{$cfg->{$parms->info}}, $provider;

      # and register the handler as an authentication provider
      register_provider($provider);
    }

    # yeah, that's not a perfect check, but...
  }

  # pass the directive back to Apache "unprocessed"
  return Apache2::Const::DECLINE_CMD;
}

sub DIR_CREATE {
  return bless { digest => [],
                 basic  => [], }, shift;
}

sub DIR_MERGE {
  my ($base, $add) = @_;

  my %new = (%$add, %$base);

  return bless \%new, ref($base);
}

1;

__END__

=head1 NAME

Apache::AuthenHook - Perl API for Apache 2.1 authentication

=head1 SYNOPSIS

  PerlLoadModule Apache::AuthenHook

  PerlModule My::OtherProvider

  <Location /digest>
    Require valid-user
    AuthType Digest
    AuthName realm1

    AuthDigestProvider My::DigestProvider file My::OtherProvider::digest

    AuthUserFile realm1
  </Location>

  <Location /basic>
    Require valid-user
    AuthType Basic
    AuthName foorealm

    AuthBasicProvider My::OtherProvider::basic file My::BasicProvider

    AuthUserFile realm1
  </Location>

=head1 DESCRIPTION

Apache::AuthenHook offers access to the 2.1 Apache authentication
API in Perl.  This is different than the authentication API
from Apache 1.3 or even Apache 2.0, but in its differences lies
strength.

For a full description of how authentication works in 2.1, see

http://www.serverwatch.com/tutorials/article.php/2202671

Basically, the difference between 2.0 and 2.1 is that authentication
is now delegated to providers, and each provider has a specific
purpose.  For instance, mod_authn_file covers gleaning the password
from an .htpasswd or .htdigest file, while mod_auth_basic covers
the Basic dialogue between the client and server, regardless 
of the source of the password.  The best part of all this (to me)
is that Digest authentication is also delegated out - 
mod_auth_digest now handles all the intricacies of Digest
authentication (including the elusive MSIE support) which
means you don't need to worry about them (and neither do I).
All that Digest authentication requires is *some* authentication
provider to provide user credentials - this can be via
mod_authn_file or another mechanism of your choosing.

Apache::AuthenHook registers and coordinates the use of Perl
handlers as authentication providers.

How does this affect you?  Read on...

=head1 EXAMPLE

Say you want to enable Digest authentication in your Apache 2.1 server...

  PerlLoadModule Apache::AuthenHook

  <Location /digest>
    Require valid-user
    AuthType Digest
    AuthName realm1

    AuthDigestProvider My::DigestProvider file

    AuthUserFile realm1
  </Location>

This configuration means that My::DigestProvider will be
responsible for providing user credentials for requests to
/digest.   if My::DigestProvider finds a suitable user, 
mod_auth_digest will verify those credentials and take care of
setting all the proper headers, set the proper HTTP response
status, and so on.  If My::DigestProvider cannot find a matching
user it can decide what to do next - either pass the user to
the next provider (in this case the default file provider,
which will use the flat file "realm1") or decide that no user
means no access.

Here is a simple My::DigestProvider

  use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED);

  sub handler {

    my ($r, $user, $realm, $hash) = @_;

    # user1 at realm1 is found - pass to mod_auth_digest
    if ($user eq 'user1' && $realm eq 'realm1') {
      $$hash = 'eee52b97527306e9e8c4613b7fa800eb';
      return Apache2::Const::OK;
    }

    # user2 is denied outright
    if ($user eq 'user2' && $realm eq 'realm1') {
      return Apache2::Const::HTTP_UNAUTHORIZED;
    }

    # all others are passed along to the next provider
    return Apache2::Const::DECLINED;
  }

isn't that easy?

the only thing that is a bit tricky here is $$hash.  the fourth
argument passed to your handler, $hash, is a reference to
to a simple scalar that needs to be populated with the MD5 hash of 
the user:realm:password combination you determine for the 
incoming user.  this may seem a bit strange, but it is actually
exactly how things work over in Apache C land, so I guess that
makes it ok.

as you can see, returning OK means "user found" and requires
that $$hash be populated - mod_auth_digest will take care 
of determining whether the hash matches the incoming Digest
criteria.  returning HTTP_UNAUTHORIZED (which is the same
as the former and still available AUTH_REQUIRED constant) 
means "no access." returning DECLINED means "some other provider
can try."

The steps are remarkably similar for Basic authentication, first

  <Location /basic>
    Require valid-user
    AuthType Basic
    AuthName foorealm

    AuthBasicProvider My::BasicProvider file

    AuthUserFile realm1
  </Location>

then

  use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED);

  sub handler {

    my ($r, $user, $password) = @_;

    # user1/basic1 is ok
    if ($user eq 'user1' && $password eq 'basic1') {
      return Apache2::Const::OK;
    }

    # user2 is denied outright
    if ($user eq 'user2') {
      return Apache2::Const::HTTP_UNAUTHORIZED;
    }

    # all others are passed along to the next provider
    return Apache2::Const::DECLINED;
  }

In the case of Basic authentication, the return codes mean
essentially the same thing.  The one exception is that OK
means that you have checked the user against the password 
and have found that they match (as opposed to with Digest, 
where the actual verification is not done by you).

These explanations should be enough to get you going - 
see the files in the test suite for more examples.

=head1 NOTES

This has been tested under the prefork MPM only, using 
mostly Perl 5.9.0 (as well as some 5.8.0).  It will not
work under threaded MPMs - soon, just not yet.

=head1 FEATURES/BUGS

This is very much so alphaware, so beware - bugs may lurk
in unexpected places.  there is one bug that is outside
of my control, though, and concerns MSIE and Digest
authentication for URIs that include query strings.  see

http://httpd.apache.org/docs-2.0/mod/mod_auth_digest.html

one workaround for this issue is is to use POST instead of 
GET for your forms.

A limitation of this interface is that you can't use Perl 
providers that are not at least two levels deep - 
the criterion for registering a Perl
provider is a simple check for a double-colon.
for example, My::Provider will work while Provider won't
(although Provider::handler will).  anyway, single
level handlers are rare, so fixing it would be a lot
of trouble for little benefit.

=head1 AUTHOR

Geoffrey Young E<lt>geoff@modperlcookbook.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2003, Geoffrey Young

All rights reserved.

This module is free software.  It may be used, redistributed
and/or modified under the same terms as Perl itself.

=cut
