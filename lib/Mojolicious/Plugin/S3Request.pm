package Mojolicious::Plugin::S3Request;

use Mojo::Base 'Mojolicious::Plugin';
use Digest::SHA qw(hmac_sha256 hmac_sha256_hex sha256_hex);
use Mojo::Date;
use Mojo::JSON qw(encode_json);
use Mojo::UserAgent;
use Mojo::Util qw(monkey_patch trim);

monkey_patch 'Mojo::Date', to_ymd => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02d', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3];
};

monkey_patch 'Mojo::Date', to_ymdhms => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02dT%02d%02d%02dZ', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3], $gmtime[2], $gmtime[1], $gmtime[0];
};

our $VERSION = '0.001';

my $AWS_AUTH_ALG = 'AWS4-HMAC-SHA256';
my $AWS_HOST = 's3.amazonaws.com';
my $AWS_REQUEST = 'aws4_request';
my $AWS_SERVICE = 's3';

sub register {
	my ( $self, $app, $conf ) = @_;

	$self->{conf} = $conf || {};

	# Required
	$self->{conf}->{access_key_id} || die 'Access key id value is mandatory.';
	$self->{conf}->{access_key}    || die 'Access key value is mandatory.';
	$self->{conf}->{bucket}        || die 'A bucket value is mandatory.';

	# Defaults if not provided
	$self->{conf}->{protocol} ||= 'https://';
	$self->{conf}->{region}   ||= 'us-east-1';

	$app->helper( 's3.bucket_url' => sub {
		$self->{conf}->{protocol} . $self->_bucket_path . '/';
	});

	$app->helper( 's3.get_file' => sub {
		my ( $c, $filename ) = @_;
		my $date = Mojo::Date->new;

		my $headers = $self->_headers( $date );
		$headers->{authorization} = $self->_auth_header( 'GET', $date, $filename, $headers );

		my $tx = $c->ua->get( $self->{conf}->{protocol} . $self->_bucket_path . '/' . $filename => $headers );
		#say 'GET: ' . $tx->res->code;

		return $tx->res if $tx->res->code == 200;
		return;
	});

	$app->helper( 's3.put_file' => sub {
		my ( $c, $filename, $size, $type, $content ) = @_;
		my $date = Mojo::Date->new;

		my $headers = $self->_headers( $date );
		$headers->{'content-length'} = $size;
		$headers->{'content-type'} = $type;
		$headers->{'x-amz-content-sha256'} = sha256_hex( $content );
		$headers->{authorization} = $self->_auth_header( 'PUT', $date, $filename, $headers );

		my $tx = $c->ua->put( $self->{conf}->{protocol} . $self->_bucket_path . '/' . $filename => $headers => $content );
		#say 'PUT: ' . $tx->res->code;
		#say $tx->res->body;
		return 1 if $tx->res->code == 200;
		return;
	});

	$app->helper( 's3.delete_file' => sub {
		my ( $c, $filename ) = @_;
		my $date = Mojo::Date->new;

		my $headers = $self->_headers( $date );
		$headers->{authorization} = $self->_auth_header( 'DELETE', $date, $filename, $headers );

		my $tx = $c->ua->delete( $self->{conf}->{protocol} . $self->_bucket_path . '/' . $filename => $headers );
		#say 'DELETE: ' . $tx->res->code;
		#say $tx->res->body;
		return 1 if $tx->res->code == 204;
		return;
	});

	$app->helper( 's3.move_file' => sub {
		my ( $c, $former_filename, $filename ) = @_;
		my $date = Mojo::Date->new;

		my $headers = $self->_headers( $date );
		$headers->{'x-amz-copy-source'} = $self->{conf}->{bucket} . '/' . $former_filename;
		$headers->{authorization} = $self->_auth_header( 'PUT', $date, $filename, $headers );

		my $tx = $c->ua->put( $self->{conf}->{protocol} . $self->_bucket_path . '/' . $filename => $headers );
		#say 'PUT: ' . $tx->res->code;
		#say $tx->res->body;

		$c->s3->delete_file( $former_filename ) if $tx->res->code == 200;
		return 1 if $tx->res->code == 200;
		return;
	});

	$app->helper( 's3.browser_policy' => sub {
		my ( $c, $params ) = @_;
		my $date = Mojo::Date->new;
		my $credential = $self->_credential( $date );

		my $policy = encode_json({
			expiration => Mojo::Date->new( time + 900 )->to_datetime,
			conditions => [
				{bucket => $self->{conf}->{bucket}},
				{'x-amz-algorithm' => $AWS_AUTH_ALG},
				{'x-amz-credential' => $credential},
				{'x-amz-date' => $date->to_ymdhms},
				{acl => 'public-read'},
				{key => $params->{filename}},
				{'content-type' => $params->{filetype}},
				['content-length-range', 0, $params->{filesize}],
				{success_action_status => '200'}
			]
		});

		my $base64_policy = $c->b( $policy )->b64_encode('');

		return {
			'x-amz-algorithm' => $AWS_AUTH_ALG,
			'x-amz-credential' => $credential,
			'x-amz-date' => $date->to_ymdhms,
			acl => 'public-read',
			key => $params->{filename},
			'content-type' => $params->{filetype},
			success_action_status => '200',
			policy => $base64_policy,
			'x-amz-signature' => $self->_sign_the_string( $base64_policy ),
		};
	});

	$app->helper( 's3.path' => sub { join '/', @_[ 1 .. $#_ ] });
}

sub _auth_header {
	my ( $self, $method, $date, $filename, $raw_headers ) = @_;

	my $headers = {};
	map { $headers->{lc trim $_} = $raw_headers->{$_} } keys %$raw_headers;

	my $string_to_sign = $self->_string_to_sign( $self->_canonical_request( $method, $filename, $headers ), $date );

	my $signature = $self->_sign_the_string( $string_to_sign, $self->{conf}->{access_key}, $date->to_ymd );

	my $auth = $AWS_AUTH_ALG;
	$auth .= ' Credential=' . $self->_credential( $date ) . ',';
	$auth .= 'SignedHeaders=' . ( join ';', sort keys %$headers ) . ',';
	$auth .= 'Signature=' . $signature;
}

sub _bucket_path {
	$_[0]->{conf}->{bucket} . '.' . $AWS_HOST;
}

sub _canonical_request {
	my ( $self, $method, $filename, $headers ) = @_;
	my $canonical_request = $method . "\n";
	$canonical_request .=  '/' . $filename . "\n";
	$canonical_request .= "\n";
	$canonical_request .= $_ . ':' . $headers->{$_} . "\n" for sort keys %$headers;
	$canonical_request .= "\n" . ( join ';', sort keys %$headers ) . "\n";
	$canonical_request .= $headers->{'x-amz-content-sha256'};
}

sub _credential {
	$_[0]->{conf}->{access_key_id} . '/' . $_[1]->to_ymd . '/' . $_[0]->{conf}->{region} . "/$AWS_SERVICE/$AWS_REQUEST";
}

sub _headers {
	return {
		date => $_[1]->to_string,
		host => $_[0]->_bucket_path,
		'x-amz-content-sha256' => sha256_hex( 'UNSIGNED-PAYLOAD' ),
	};
}

sub _string_to_sign {
	my ( $self, $canonical_request, $date ) = @_;
	my $string_to_sign = "$AWS_AUTH_ALG\n";
	$string_to_sign .= $date->to_string . "\n";
	$string_to_sign .= $date->to_ymd . '/' . $self->{conf}->{region} . "/$AWS_SERVICE/$AWS_REQUEST\n";
	$string_to_sign .= sha256_hex( $canonical_request );
}

sub _signing_key {
	my $self = shift;
	hmac_sha256( $AWS_REQUEST,
		hmac_sha256( $AWS_SERVICE,
			hmac_sha256( $self->{conf}->{region},
				hmac_sha256( Mojo::Date->new->to_ymd, 'AWS4' . $self->{conf}->{access_key} )
			)
		)
	);
}

sub _sign_the_string {
	hmac_sha256_hex( $_[1], $_[0]->_signing_key );
}

1;

__END__

=encoding utf-8

=head1 NAME

Mojolicious::Plugin::S3Request - Mojolicious Plugin for basic S3 AWS4 requests.

=head1 VERSION

0.001

=head1 SOURCE REPOSITORY

L<http://github.com/keenlinks/Mojolicious-Plugin-S3Request>

=head1 AUTHOR

Scott Kiehn E<lt>sk.keenlinks@gmail.comE<gt>

=head1 COPYRIGHT

Copyright 2017 - Scott Kiehn

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

=cut
