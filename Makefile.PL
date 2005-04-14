#!perl

use 5.008;

use ModPerl::MM ();
use Apache::Test;
use Apache::TestMM qw(test clean);
use Apache::TestRunPerl ();

Apache::TestMM::filter_args();

Apache::TestRunPerl->generate_script(bugreport => <<EOF);
+-------------------------------------------------------------------+
| this module is experimental, use at your own risk                 |
+-------------------------------------------------------------------+
EOF

ModPerl::MM::WriteMakefile(
  NAME          => 'Apache::AuthenHook',
  VERSION_FROM  => 'AuthenHook.pm',
  PREREQ_PM     => { mod_perl2    => 0 },
);
