use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest;

# Basic auth tests

plan tests => 10, (have_lwp &&
                   have_module('mod_auth_basic'));

my $url = '/basic/index.html';

my $response = GET $url;
ok $response->code == 401;

# bad pass
$response = GET $url, username => 'user1', password => 'foo';
ok $response->code == 401;

# authenticated in the first provider
$response = GET $url, username => 'user1', password => 'basic1';
ok $response->code == 200;

# declined in the first provider
$response = GET $url, username => 'user2', password => 'basic2';
ok $response->code == 401;

# bad pass
$response = GET $url, username => 'user3', password => 'foo';
ok $response->code == 401;

# authenticated in the second provider
$response = GET $url, username => 'user3', password => 'basic3';
ok $response->code == 200;

# declined in the second provider
$response = GET $url, username => 'user4', password => 'basic4';
ok $response->code == 401;

# bad pass
$response = GET $url, username => 'user5', password => 'foo';
skip(! have_module('mod_authn_file'), $response->code == 401);

# authenticated in the file provider
$response = GET $url, username => 'user5', password => 'basic5';
skip(! have_module('mod_authn_file'), $response->code == 200);

# non-existent anywhere
$response = GET $url, username => 'user6', password => 'basic6';
ok $response->code == 401;
