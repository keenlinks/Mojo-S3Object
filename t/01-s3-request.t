use Mojo::Base -strict;

use Test::More;
use Mojolicious::Lite;
use Test::Mojo;

plugin 'Mojolicious::Plugin::S3Request' => {
  access_key => 'secret_access_key',
  access_key_id => 'access_key_id',
  bucket => 'my_bucket'
};

my $t = Test::Mojo->new;
my $c = $t->app->build_controller;

ok( 1 == 1 );

done_testing();
