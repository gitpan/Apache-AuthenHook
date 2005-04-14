use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest;
use Apache::TestUtil;

# test DIR_MERGE logic

plan tests => 6, (need_lwp &&
                  need_module('mod_auth_digest') &&
                  need_module('mod_auth_basic'));

my $url = '/digest/merge/index.html';
my $response = GET $url;
ok t_cmp($response->code,
         401,
         "GET $url");

# authenticated
$response = GET $url, username => 'testuser', password => 'testpass';
ok t_cmp($response->code,
         200,
         "GET $url, username => 'testuser', password => 'testpass'");

# bad pass
$response = GET $url, username => 'testuser', password => 'foo';
ok t_cmp($response->code,
         401,
         "GET $url, username => 'testuser', password => 'foo'");

$url = '/basic/merge/index.html';

$response = GET $url;
ok t_cmp($response->code,
         401,
         "GET $url");

# authenticated
$response = GET $url, username => 'testuser', password => 'testpass';
ok t_cmp($response->code,
         200,
         "GET $url, username => 'testuser', password => 'testpass'");

# bad pass
$response = GET $url, username => 'testuser', password => 'foo';
ok t_cmp($response->code,
         401,
         "GET $url, username => 'testuser', password => 'foo'");
