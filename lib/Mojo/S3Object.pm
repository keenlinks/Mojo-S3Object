package Mojo::S3Object;

use Mojo::Base -base;
use Carp;
use Digest::SHA qw(hmac_sha256 hmac_sha256_hex sha256_hex);
use Mojo::Date;
use Mojo::IOLoop;
use Mojo::JSON qw(encode_json);
use Mojo::UserAgent;
use Mojo::Util qw(b64_encode monkey_patch trim);

our $VERSION = '0.02_2';

# Required
has access_key => sub { die 'Parameter "access_key" is mandatory in the constructor.' };
has access_key_id => sub { die 'Parameter "access_key_id" is mandatory in the constructor.' };
has bucket => sub { die 'Parameter "bucket" is mandatory in the constructor.' };

# Defaults if not provided
has protocol => sub { 'https://' };
has region => sub { 'us-east-1' };

# Defaults
has aws_auth_alg => 'AWS4-HMAC-SHA256';
has aws_host => 's3.amazonaws.com';
has aws_request => 'aws4_request';
has aws_service => 's3';

has bucket_path => sub { $_[0]->bucket . '.' . $_[0]->aws_host };
has bucket_url => sub { $_[0]->protocol . $_[0]->bucket_path };

has ua => sub { state $ua = Mojo::UserAgent->new };

monkey_patch 'Mojo::Date', to_ymd => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02d', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3];
};

monkey_patch 'Mojo::Date', to_ymdhms => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02dT%02d%02d%02dZ', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3], $gmtime[2], $gmtime[1], $gmtime[0];
};

sub browser_policy {
	my ( $self, $params ) = @_;
	my $date = Mojo::Date->new;
	my $credential = $self->_credential( $date );

	my $policy = encode_json({
		expiration => Mojo::Date->new( time + 900 )->to_datetime,
		conditions => [
			{bucket => $self->bucket},
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

	my $base64_policy = b64_encode $policy, '';

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
}

sub copy {
	my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
	my ( $self, $former_object_name, $s3_object_name ) = @_;

	my $headers = $self->_headers( 'PUT', $s3_object_name, { 'x-amz-copy-source' => $self->bucket . '/' . $former_object_name });

	return $self->ua->put( $self->_object_url( $s3_object_name ) => $headers )->res->code == 200 ? 'ok' : undef
		unless $cb;

	$self->_ioloop->delay(
		sub {
			$self->ua->put( $self->_object_url( $s3_object_name ) => $headers, shift->begin );
		},
		sub {
			return $self->$cb( pop->res->code == 200 ? 'ok' : undef );
		}
	)->wait;
}

sub delete {
	my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
	my ( $self, $s3_object_name ) = @_;

	my $headers = $self->_headers( 'DELETE', $s3_object_name );

	return $self->ua->delete( $self->_object_url( $s3_object_name ) => $headers )->res->code == 204 ? 'ok' : undef
		unless $cb;

	$self->_ioloop->delay(
		sub {
			$self->ua->delete( $self->_object_url( $s3_object_name ) => $headers, shift->begin );
		},
		sub {
			return $self->$cb( pop->res->code == 204 ? 'ok' : undef );
		}
	)->wait;
}

sub get {
	my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
	my ( $self, $s3_object_name ) = @_;

	my $headers = $self->_headers( 'GET', $s3_object_name );

	unless ( $cb ) {
		my $tx = $self->ua->get( $self->_object_url( $s3_object_name ) => $headers );
		return $tx->res->code == 200 ? $tx->res : undef;
	}

	$self->_ioloop->delay(
		sub {
			$self->ua->get( $self->_object_url( $s3_object_name ) => $headers, shift->begin );
		},
		sub {
			my $tx = pop;
			return $self->$cb( $tx->res->code == 200 ? $tx->res : undef );
		}
	)->wait;
}

sub put {
	my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
	my ( $self, $s3_object_name, $asset, $content_type ) = @_;

	croak 'You want to use the "upload" method. "Put" method does not use Mojo::Upload.' if ref $asset eq 'Mojo::Upload';

	my $content = $asset->slurp;
	my $prep = { 'content-length' => $asset->size, 'x-amz-content-sha256' => sha256_hex( $content ) };
	$prep->{'content-type'} = $content_type if $content_type;

	my $headers = $self->_headers( 'PUT', $s3_object_name, $prep );

	return $self->ua->put( $self->_object_url( $s3_object_name ) => $headers => $content )->res->code == 200 ? 'ok' : 'oops'
		unless $cb;

	$self->_ioloop->delay(
		sub {
			$self->ua->put( $self->_object_url( $s3_object_name ) => $headers => $content, shift->begin );
		},
		sub {
			my $tx = pop;
			return $self->$cb( $tx->res->code == 200 ? 'ok' : undef );
		}
	)->wait;
}

sub upload {
	my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
	my ( $self, $s3_object_name, $upload ) = @_;

	croak 'You want to use the "put" method. "Upload" method for use with Mojo::Upload.' unless ref $upload eq 'Mojo::Upload';

	return $self->put( $s3_object_name, $upload->asset, $upload->headers->content_type, $cb );
}

sub _auth_header {
	my ( $self, $method, $date, $s3_object_name, $raw_headers ) = @_;

	my $headers = {};
	map { $headers->{lc trim $_} = $raw_headers->{$_} } keys %$raw_headers;

	my $string_to_sign = $self->_string_to_sign( $self->_canonical_request( $method, $s3_object_name, $headers ), $date );

	my $signature = $self->_sign_the_string( $string_to_sign, $self->access_key, $date->to_ymd );

	my $auth = $self->aws_auth_alg;
	$auth .= ' Credential=' . $self->_credential( $date ) . ',';
	$auth .= 'SignedHeaders=' . ( join ';', sort keys %$headers ) . ',';
	$auth .= 'Signature=' . $signature;
}

sub _canonical_request {
	my ( $self, $method, $s3_object_name, $headers ) = @_;
	my $canonical_request = $method . "\n";
	$canonical_request .=  '/' . $s3_object_name . "\n";
	$canonical_request .= "\n";
	$canonical_request .= $_ . ':' . $headers->{$_} . "\n" for sort keys %$headers;
	$canonical_request .= "\n" . ( join ';', sort keys %$headers ) . "\n";
	$canonical_request .= $headers->{'x-amz-content-sha256'};
}

sub _credential {
	$_[0]->access_key_id . '/' . $_[1]->to_ymd . '/' . $_[0]->region . '/' . $_[0]->aws_service . '/' . $_[0]->aws_request;
}

sub _headers {
	my ( $self, $method, $s3_object_name, $headers ) = @_;
	my $date = Mojo::Date->new;
	$headers->{date} = $date->to_string;
	$headers->{host} = $self->bucket_path;
	$headers->{'x-amz-content-sha256'} = sha256_hex( 'UNSIGNED-PAYLOAD' ) unless defined $headers->{'x-amz-content-sha256'};
	$headers->{authorization} = $self->_auth_header( $method, $date, $s3_object_name, $headers );
	return $headers;
}

sub _ioloop { Mojo::IOLoop->singleton }

sub _object_url { $_[0]->bucket_url . '/' . $_[1] }

sub _signing_key {
	my $self = shift;
	hmac_sha256( $self->aws_request,
		hmac_sha256( $self->aws_service,
			hmac_sha256( $self->region,
				hmac_sha256( Mojo::Date->new->to_ymd, 'AWS4' . $self->access_key )
			)
		)
	);
}

sub _sign_the_string { hmac_sha256_hex( $_[1], $_[0]->_signing_key ) }

sub _string_to_sign {
	my ( $self, $canonical_request, $date ) = @_;
	my $string_to_sign = $self->aws_auth_alg . "\n";
	$string_to_sign .= $date->to_string . "\n";
	$string_to_sign .= $date->to_ymd . '/' . $self->region . '/' . $self->aws_service . '/' . $self->aws_request . "\n";
	$string_to_sign .= sha256_hex( $canonical_request );
}

1;
__END__

=encoding utf-8

=head1 NAME

Mojo::S3Object - Mojo interface to S3 objects.

=head1 VERSION

0.02_2

=head1 SOURCE REPOSITORY

L<http://github.com/keenlinks/Mojo-S3Objects>

=head1 AUTHOR

Scott Kiehn E<lt>sk.keenlinks@gmail.comE<gt>

=head1 COPYRIGHT

Copyright 2017 - Scott Kiehn

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

=cut
