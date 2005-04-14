package My::Basic1;

use Apache2::Log;

use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR);

use strict;

sub basic {

  my ($r, $user, $password) = @_;

  $r->log->info('called ', join ' : ', __PACKAGE__, @_);

  return Apache2::Const::HTTP_INTERNAL_SERVER_ERROR unless $r->isa('Apache2::RequestRec');

  # user1/basic1 is ok
  if ($user eq 'user1' && $password eq 'basic1') {
    return Apache2::Const::OK;
  }

  # user2 is denied outright
  if ($user eq 'user2') {
    return Apache2::Const::HTTP_UNAUTHORIZED;
  }

  # all others are passed along
  return Apache2::Const::DECLINED;
}

1;
