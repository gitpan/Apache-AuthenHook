package My::TestUser;

use Apache::RequestRec;

use Apache::Const -compile => qw(OK HTTP_UNAUTHORIZED);

use strict;

sub handler {

  my $r = shift;

  if ($r->ap_auth_type eq 'Digest') {

   my ($user, $realm, $hash) = @_;

   if ($user eq 'testuser' && $realm eq 'realm1') {
     $$hash = '0a2e8a13afd0ea7b7e78cc22725bf06a';
     return Apache::OK;
   }
  }
  else {

   my ($user, $password) = @_;

   if ($user eq 'testuser' && $password eq 'testpass') {
     return Apache::OK;
   }
  }

  return Apache::HTTP_UNAUTHORIZED;
}

1;
