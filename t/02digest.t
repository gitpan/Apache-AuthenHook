use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest;
use Apache::TestUtil;

# Digest auth tests

plan tests => 10, (have_lwp &&
                   have_module('mod_auth_digest'));

my $url = '/digest/index.html';

my $response = GET $url;
ok t_cmp(401,
         $response->code,
         "GET $url");

# bad pass
$response = GET $url, username => 'user1', password => 'foo';
ok t_cmp(401,
         $response->code,
         GET $url, username => 'user1', password => 'foo');

# authenticated in the first provider
$response = GET $url, username => 'user1', password => 'digest1';
ok t_cmp(200,
         $response->code,
         GET $url, username => 'user1', password => 'digest1');

# declined in the first provider
$response = GET $url, username => 'user2', password => 'digest2';
ok t_cmp(401,
         $response->code,
         "GET $url, username => 'user2', password => 'digest2'");

# bad pass
$response = GET $url, username => 'user3', password => 'foo';
ok t_cmp(401,
         $response->code,
         "GET $url, username => 'user3', password => 'foo'");

# authenticated in the second provider
$response = GET $url, username => 'user3', password => 'digest3';
ok t_cmp(200,
         $response->code,
         "GET $url, username => 'user3', password => 'digest3'");

# declined in the second provider
$response = GET $url, username => 'user4', password => 'digest4';
ok t_cmp(401,
         $response->code,
         "GET $url, username => 'user4', password => 'digest4'");

# bad pass
$response = GET $url, username => 'user5', password => 'foo';
skip(! have_module('mod_authn_file'),
     t_cmp(401,
           $response->code,
           "GET $url, username => 'user5', password => 'foo'")
    );

# authenticated in the file provider
$response = GET $url, username => 'user5', password => 'digest5';
skip(! have_module('mod_authn_file'),
     t_cmp(200,
           $response->code,
           "GET $url, username => 'user5', password => 'digest5'")
    );

# non-existent anywhere
$response = GET $url, username => 'user6', password => 'digest6';
ok t_cmp(401,
         $response->code,
         "GET $url, username => 'user6', password => 'digest6'");
