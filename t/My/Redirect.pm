package My::Redirect;

use Apache2::RequestRec ();
use Apache2::SubRequest ();

use Apache2::Const -compile => qw(OK);

use strict;

sub handler {
  shift->internal_redirect('/digest/index.html');
  return Apache2::Const::OK;
}
1;
