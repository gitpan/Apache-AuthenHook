use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest;

# test DIR_MERGE logic

plan tests => 6, (have_lwp &&
                  have_module('mod_auth_digest') &&
                  have_module('mod_auth_basic'));

my $url = '/digest/merge/index.html';
my $response = GET $url;
ok $response->code == 401;

# authenticated
$response = GET $url, username => 'testuser', password => 'testpass';
ok $response->code == 200;

# bad pass
$response = GET $url, username => 'testuser', password => 'foo';
ok $response->code == 401;

$url = '/basic/merge/index.html';

$response = GET $url;
ok $response->code == 401;

# authenticated
$response = GET $url, username => 'testuser', password => 'testpass';
ok $response->code == 200;

# bad pass
$response = GET $url, username => 'testuser', password => 'foo';
ok $response->code == 401;
