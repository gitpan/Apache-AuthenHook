package My::Basic2;

use Apache::Log;

use Apache::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR);

use strict;

sub handler {

  my ($r, $user, $password) = @_;

  $r->log->info('called ', join ' : ', __PACKAGE__, @_);

  return Apache::HTTP_INTERNAL_SERVER_ERROR unless $r->isa('Apache::RequestRec');

  # user1 was ok in My::Basic1
  if ($user eq 'user1') {
    return Apache::HTTP_UNAUTHORIZED;
  }

  # user2 was denied in My::Basic1
  if ($user eq 'user2') {
    return Apache::OK;
  }

  # user3/digest3 is ok
  if ($user eq 'user3' && $password eq 'basic3') {
    return Apache::OK;
  }

  # decline user4 outright
  if ($user eq 'user4') {
    return Apache::HTTP_UNAUTHORIZED;
  }

  # all others are passed along
  return Apache::DECLINED;
}

1;
