package My::Redirect;

use Apache::RequestRec ();
use Apache::SubRequest ();

use Apache::Const -compile => qw(OK);

use strict;

sub handler {
  shift->internal_redirect('/digest/index.html');
  return Apache::OK;
}
1;
