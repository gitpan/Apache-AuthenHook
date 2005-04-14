package My::Basic2;

use Apache2::Log;

use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR);

use strict;

sub handler {

  my ($r, $user, $password) = @_;

  $r->log->info('called ', join ' : ', __PACKAGE__, @_);

  return Apache2::Const::HTTP_INTERNAL_SERVER_ERROR unless $r->isa('Apache2::RequestRec');

  # user1 was ok in My::Basic1
  if ($user eq 'user1') {
    return Apache2::Const::HTTP_UNAUTHORIZED;
  }

  # user2 was denied in My::Basic1
  if ($user eq 'user2') {
    return Apache2::Const::OK;
  }

  # user3/digest3 is ok
  if ($user eq 'user3' && $password eq 'basic3') {
    return Apache2::Const::OK;
  }

  # decline user4 outright
  if ($user eq 'user4') {
    return Apache2::Const::HTTP_UNAUTHORIZED;
  }

  # all others are passed along
  return Apache2::Const::DECLINED;
}

1;
