#!perl

use 5.008;

use Apache2 ();
use ModPerl::MM ();
use Apache::Test;
use Apache::TestMM qw(test clean);
use Apache::TestRunPerl ();

Apache::TestMM::filter_args();

die "Sorry, Apache 2.1.0 or higher is required to ",
    "compile (and use) Apache::AuthenHook\n"
  unless have_min_apache_version('2.1');

Apache::TestRunPerl->generate_script();

ModPerl::MM::WriteMakefile(
  NAME          => 'Apache::AuthenHook',
  VERSION_FROM  => 'AuthenHook.pm',
  PREREQ_PM     => { mod_perl    => 1.99_11 },
);
