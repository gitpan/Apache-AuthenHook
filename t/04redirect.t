use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest;

# make sure that internal redirects are handled properly

plan tests => 10, (have_lwp &&
                   have_module('mod_auth_digest'));

my $url = '/redirect/index.html';

my $response = GET $url;
ok $response->code == 401;

# bad pass
$response = GET $url, username => 'user1', password => 'foo';
ok $response->code == 401;

# authenticated in the first provider
$response = GET $url, username => 'user1', password => 'digest1';
ok $response->code == 200;

# declined in the first provider
$response = GET $url, username => 'user2', password => 'digest2';
ok $response->code == 401;

# bad pass
$response = GET $url, username => 'user3', password => 'foo';
ok $response->code == 401;

# authenticated in the second provider
$response = GET $url, username => 'user3', password => 'digest3';
ok $response->code == 200;

# declined in the second provider
$response = GET $url, username => 'user4', password => 'digest4';
ok $response->code == 401;

# bad pass
$response = GET $url, username => 'user5', password => 'foo';
skip(! have_module('mod_authn_file'), $response->code == 401);

# authenticated in the file provider
$response = GET $url, username => 'user5', password => 'digest5';
skip(! have_module('mod_authn_file'), $response->code == 200);

# non-existent anywhere
$response = GET $url, username => 'user6', password => 'digest6';
ok $response->code == 401;
