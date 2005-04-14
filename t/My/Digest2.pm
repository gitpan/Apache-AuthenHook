package My::Digest2;

use Apache2::Log;

use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR);

use strict;

sub digest {

  my ($r, $user, $realm, $hash) = @_;

  $r->log->info('called ', join ' : ', __PACKAGE__, @_);

  return Apache2::Const::HTTP_INTERNAL_SERVER_ERROR unless $r->isa('Apache2::RequestRec');

  # user1 was ok in My::Digest1
  if ($user eq 'user1' && $realm eq 'realm1') {
    return Apache2::Const::HTTP_UNAUTHORIZED;
  }

  # user2 was denied in My::Digest1
  if ($user eq 'user2' && $realm eq 'realm1') {
    return Apache2::Const::OK;
  }

  # user3/digest3 is ok
  if ($user eq 'user3' && $realm eq 'realm1') {
    $$hash = '00f4ee3be98d1c8d83bc526a9bad5308';
    return Apache2::Const::OK;
  }

  # decline user4 outright
  if ($user eq 'user4' && $realm eq 'realm1') {
    return Apache2::Const::HTTP_UNAUTHORIZED;
  }

  # all others are passed along
  return Apache2::Const::DECLINED;
}

1;
