package My::Basic1;

use Apache::Log;

use Apache::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR);

use strict;

sub basic {

  my ($r, $user, $password) = @_;

  $r->log->info('called ', join ' : ', __PACKAGE__, @_);

  return Apache::HTTP_INTERNAL_SERVER_ERROR unless $r->isa('Apache::RequestRec');

  # user1/basic1 is ok
  if ($user eq 'user1' && $password eq 'basic1') {
    return Apache::OK;
  }

  # user2 is denied outright
  if ($user eq 'user2') {
    return Apache::HTTP_UNAUTHORIZED;
  }

  # all others are passed along
  return Apache::DECLINED;
}

1;
