use File::Spec;
use File::Find qw(find);

use strict;

# check that documentation isn't broken

eval {
  # if we have both Test::More and Test::Pod we're good to go
  require Test::More;
  Test::More->import;
  require Test::Pod;
  Test::Pod->import;
};

if ($@) {
  # otherwise we need to plan accordingly - either
  # using Test::More or Test.pm syntax
  eval {
    require Test::More;
  };

  if ($@) {
    require Test;
    Test->import;
    plan(tests => 0);
  }
  else {
    plan(skip_all => 'Test::Pod required for testing POD');
  }
}
else {
  my @files;

  find(
    sub { push @files, $File::Find::name if m!\.p(m|od|l)$! },
    File::Spec->catfile(qw(.. blib lib))
  );

  plan(tests => scalar @files);

  foreach my $file (@files) {
    # use the older Test::Pod interface for maximum back compat
    pod_ok($file);
  }
}
