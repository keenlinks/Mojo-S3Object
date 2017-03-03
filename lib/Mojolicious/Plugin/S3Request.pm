package Mojolicious::Plugin::S3Request;

use Mojo::Base 'Mojolicious::Plugin';
use Digest::SHA qw(hmac_sha256 hmac_sha256_hex sha256_hex);
use Mojo::Date;
use Mojo::IOLoop;
use Mojo::JSON qw(encode_json);
use Mojo::Util qw(monkey_patch trim);

monkey_patch 'Mojo::Date', to_ymd => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02d', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3];
};

monkey_patch 'Mojo::Date', to_ymdhms => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02dT%02d%02d%02dZ', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3], $gmtime[2], $gmtime[1], $gmtime[0];
};

our $VERSION = '0.02_1';

has ioloop => sub { Mojo::IOLoop->new };
has aws_auth_alg => 'AWS4-HMAC-SHA256';
has aws_host => 's3.amazonaws.com';
has aws_request => 'aws4_request';
has aws_service => 's3';

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

	$app->helper( 's3.bucket_url' => sub { $self->{conf}->{protocol} . $self->_bucket_path . '/' });

	$app->helper( 's3.copy_file' => sub {
		my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
		my ( $c, $former_file, $file ) = @_;

		my $headers = $self->_headers( 'PUT', $file, { 'x-amz-copy-source' => $self->{conf}->{bucket} . '/' . $former_file });

		return $c->ua->put( $self->_object_url( $file ) => $headers )->res->code == 200 ? 'ok' : undef
			unless $cb;

		$self->_loop->delay(
			sub {
				$c->ua->put( $self->_object_url( $file ) => $headers, shift->begin );
			},
			sub {
				return $self->$cb( pop->res->code == 200 ? 'ok' : undef );
			}
		)->wait;
	});

	$app->helper( 's3.delete_file' => sub {
		my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
		my ( $c, $file ) = @_;

		my $headers = $self->_headers( 'DELETE', $file );

		return $c->ua->delete( $self->_object_url( $file ) => $headers )->res->code == 204 ? 'ok' : undef
			unless $cb;

		$self->_loop->delay(
			sub {
				$c->ua->delete( $self->_object_url( $file ) => $headers, shift->begin );
			},
			sub {
				return $self->$cb( pop->res->code == 204 ? 'ok' : undef );
			}
		)->wait;
	});

	$app->helper( 's3.get_file' => sub {
		my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
		my ( $c, $file ) = @_;

		my $headers = $self->_headers( 'GET', $file );

		unless ( $cb ) {
			my $tx = $c->ua->get( $self->_object_url( $file ) => $headers );
			return $tx->res->code == 200 ? $tx->res : undef;
		}

		$self->_loop->delay(
			sub {
				$c->ua->get( $self->_object_url( $file ) => $headers, shift->begin );
			},
			sub {
				my $tx = pop;
				return $self->$cb( $tx->res->code == 200 ? $tx->res : undef );
			}
		)->wait;
	});

	$app->helper( 's3.put_file' => sub {
		my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
		my ( $c, $file, $upload ) = @_;
		my $content = $upload->asset->slurp;

		my $headers = $self->_headers( 'PUT', $file, {
			'content-length' => $upload->size,
			'content-type' => $upload->headers->content_type,
			'x-amz-content-sha256' => sha256_hex( $content )
		});

		return $c->ua->put( $self->_object_url( $file ) => $headers => $content )->res->code == 200 ? 'ok' : undef
			unless $cb;

		$self->_loop->delay(
			sub {
				$c->ua->put( $self->_object_url( $file ) => $headers => $content, shift->begin );
			},
			sub {
				return $self->$cb( pop->res->code == 200 ? 'ok' : undef );
			}
		)->wait;
	});

	$app->helper( 's3.browser_policy' => sub {
		my ( $c, $params ) = @_;
		my $date = Mojo::Date->new;
		my $credential = $self->_credential( $date );

		my $policy = encode_json({
			expiration => Mojo::Date->new( time + 900 )->to_datetime,
			conditions => [
				{bucket => $self->{conf}->{bucket}},
				{'x-amz-algorithm' => $self->aws_auth_alg},
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
			'x-amz-algorithm' => $self->aws_auth_alg,
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
}

sub _auth_header {
	my ( $self, $method, $date, $file, $raw_headers ) = @_;

	my $headers = {};
	map { $headers->{lc trim $_} = $raw_headers->{$_} } keys %$raw_headers;

	my $string_to_sign = $self->_string_to_sign( $self->_canonical_request( $method, $file, $headers ), $date );

	my $signature = $self->_sign_the_string( $string_to_sign, $self->{conf}->{access_key}, $date->to_ymd );

	my $auth = $self->aws_auth_alg;
	$auth .= ' Credential=' . $self->_credential( $date ) . ',';
	$auth .= 'SignedHeaders=' . ( join ';', sort keys %$headers ) . ',';
	$auth .= 'Signature=' . $signature;
}

sub _bucket_path {
	$_[0]->{conf}->{bucket} . '.' . $_[0]->aws_host;
}

sub _canonical_request {
	my ( $self, $method, $file, $headers ) = @_;
	my $canonical_request = $method . "\n";
	$canonical_request .=  '/' . $file . "\n";
	$canonical_request .= "\n";
	$canonical_request .= $_ . ':' . $headers->{$_} . "\n" for sort keys %$headers;
	$canonical_request .= "\n" . ( join ';', sort keys %$headers ) . "\n";
	$canonical_request .= $headers->{'x-amz-content-sha256'};
}

sub _credential {
	$_[0]->{conf}->{access_key_id} . '/' . $_[1]->to_ymd . '/' . $_[0]->{conf}->{region} . '/' . $_[0]->aws_service . '/' . $_[0]->aws_request;
}

sub _headers {
	my ( $self, $method, $file, $headers ) = @_;
	my $date = Mojo::Date->new;
	$headers->{date} = $date->to_string;
	$headers->{host} = $self->_bucket_path;
	$headers->{'x-amz-content-sha256'} = sha256_hex( 'UNSIGNED-PAYLOAD' ) unless defined $headers->{'x-amz-content-sha256'};
	$headers->{authorization} = $self->_auth_header( $method, $date, $file, $headers );
	return $headers;
}

sub _loop { $_[1] ? Mojo::IOLoop->singleton : $_[0]->ioloop }

sub _object_url { $_[0]->{conf}->{protocol} . $_[0]->_bucket_path . '/' . $_[1] }

sub _signing_key {
	my $self = shift;
	hmac_sha256( $self->aws_request,
		hmac_sha256( $self->aws_service,
			hmac_sha256( $self->{conf}->{region},
				hmac_sha256( Mojo::Date->new->to_ymd, 'AWS4' . $self->{conf}->{access_key} )
			)
		)
	);
}

sub _sign_the_string { hmac_sha256_hex( $_[1], $_[0]->_signing_key ) }

sub _string_to_sign {
	my ( $self, $canonical_request, $date ) = @_;
	my $string_to_sign = $self->aws_auth_alg . "\n";
	$string_to_sign .= $date->to_string . "\n";
	$string_to_sign .= $date->to_ymd . '/' . $self->{conf}->{region} . '/' . $self->aws_service . '/' . $self->aws_request . "\n";
	$string_to_sign .= sha256_hex( $canonical_request );
}

1;
__END__

=encoding utf-8

=head1 NAME

Mojolicious::Plugin::S3Request - Mojolicious Plugin for basic S3 AWS4 requests.

=head1 VERSION

0.02_1

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
