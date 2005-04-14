package My::TestUser;

use Apache2::RequestRec;
use Apache2::RequestUtil;
use Apache2::Access;

use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED);

use strict;

sub handler {

  my $r = shift;

  warn "trying ", $r->uri;
  warn "auth type ", $r->ap_auth_type;
  warn "auth type 2", $r->auth_type;
  if ($r->ap_auth_type eq 'Digest') {

   my ($user, $realm, $hash) = @_;

   warn "inside";
   if ($user eq 'testuser' && $realm eq 'realm1') {
     $$hash = '0a2e8a13afd0ea7b7e78cc22725bf06a';
     warn "ok";
     return Apache2::Const::OK;
   }
  }
  else {

   my ($user, $password) = @_;

   if ($user eq 'testuser' && $password eq 'testpass') {
     return Apache2::Const::OK;
   }
  }

  return Apache2::Const::HTTP_UNAUTHORIZED;
}

1;
