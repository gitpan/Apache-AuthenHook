package My::Digest1;

use Apache2::Log;

use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR);

use strict;

sub handler {

  my ($r, $user, $realm, $hash) = @_;

  $r->log->info('called ', join ' : ', __PACKAGE__, @_);

  return Apache2::Const::HTTP_INTERNAL_SERVER_ERROR unless $r->isa('Apache2::RequestRec');

  # user1/digest1 is ok
  if ($user eq 'user1' && $realm eq 'realm1') {
    $$hash = 'eee52b97527306e9e8c4613b7fa800eb';
    return Apache2::Const::OK;
  }

  # user2 is denied outright
  if ($user eq 'user2' && $realm eq 'realm1') {
    return Apache2::Const::HTTP_UNAUTHORIZED;
  }

  # all others are passed along
  return Apache2::Const::DECLINED;
}

1;
