package My::Digest1;

use Apache::Log;

use Apache::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR);

use strict;

sub handler {

  my ($r, $user, $realm, $hash) = @_;

  $r->log->info('called ', join ' : ', __PACKAGE__, @_);

  return Apache::HTTP_INTERNAL_SERVER_ERROR unless $r->isa('Apache::RequestRec');

  # user1/digest1 is ok
  if ($user eq 'user1' && $realm eq 'realm1') {
    $$hash = 'eee52b97527306e9e8c4613b7fa800eb';
    return Apache::OK;
  }

  # user2 is denied outright
  if ($user eq 'user2' && $realm eq 'realm1') {
    return Apache::HTTP_UNAUTHORIZED;
  }

  # all others are passed along
  return Apache::DECLINED;
}

1;
