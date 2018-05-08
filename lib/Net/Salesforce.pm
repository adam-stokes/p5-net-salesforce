package Net::Salesforce;

# ABSTRACT: An authentication module for Salesforce OAuth 2.

use Mojo::Base -base;
use Mojo::UserAgent;
use Mojo::URL;
use Mojo::Parameters;
use Mojo::JSON qw(decode_json encode_json);
use Digest::SHA;

has 'key';

has 'secret';

has 'redirect_uri' => 'https://localhost:8081/callback';

has 'api_host' => 'https://na15.salesforce.com/';

has 'access_token_path' => 'services/oauth2/token';

has 'authorize_path' => 'services/oauth2/authorize';

has 'scope' => 'api refresh_token';

has 'response_type' => 'code';

has 'params' => sub {
    my $self = shift;
    return {
        client_id     => $self->key,
        client_secret => $self->secret,
        redirect_uri  => $self->redirect_uri,
    };
};

has 'ua' => sub {
    my $self = shift;
    my $ua = Mojo::UserAgent->new;
    $ua->transactor->name("Net::Salesforce/$Net::Salesforce::VERSION");
    return $ua;
};

sub verify_signature {

    # TODO: fix verify
    my ($self, $payload) = @_;
    my $sha = Digest::SHA->new(256);
    $sha->hmac_sha256($self->secret);
    $sha->add($payload->{id});
    $sha->add($payload->{issued_at});
    $sha->b64digest eq $payload->{signature};
}

sub refresh {
    my ($self, $refresh_token) = @_;
    $self->params->{refresh_token} = $refresh_token;
    $self->params->{grant_type} = 'refresh_token';
    return $self->oauth2;
}

sub password {
    my $self = shift;
    $self->params->{grant_type} = 'password';
    return $self->oauth2;
}

sub authenticate {
    my ($self, $code) = @_;
    $self->params->{code} = $code;
    $self->params->{grant_type} = 'authorization_code';
    return $self->oauth2;
}

sub authorize_url {
    my $self = shift;
    $self->params->{response_type} = 'code';
    my $url = Mojo::URL->new($self->api_host)
      ->path($self->authorize_path)
      ->query($self->params);
    return $url->to_string;
}

sub access_token_url {
    my $self = shift;
    my $url  = Mojo::URL->new($self->api_host)->path($self->access_token_path);
    return $url->to_string;
}

sub oauth2 {
    my $self = shift;

    my $tx =
      $self->ua->post($self->access_token_url => form => $self->params);

    die $tx->res->body unless $tx->success;

    my $payload = decode_json($tx->res->body);

  # TODO: fix verify signature
  # die "Unable to verify signature" unless $self->verify_signature($payload);

    return $payload;
}

1;

=head1 SYNOPSIS

  use Net::Salesforce;

  my $sf = Net::Salesforce->new(
      'key'          => $ENV{SFKEY},
      'secret'       => $ENV{SFSECRET},
      'redirect_uri' => 'https://localhost:8081/callback'
  );

=attr api_host

Returns a L<Mojo::URL> of the Salesforce api host, defaults to
https://na15.salesforce.com/

=attr authorize_path

Endpoint to Salesforce's authorize page.

=attr access_token_path

Endpoint to Salesforce's access token page

=attr params

Form parameters attribute

=attr redirect_uri

Callback URI defined in your Salesforce application

=attr response_type

Response type for authorization callback

=attr scope

Scopes available as defined by the Salesforce application.

=attr secret

Acts as Salesforce client_secret

=attr key

Acts as Salesforce client_key

=attr ua

A L<Mojo::UserAgent> object.

=attr json

A L<Mojo::JSON> object.

=method verify_signature

=method refresh

=method oauth2

=method authorize_url

=method access_token_url

=method authenticate

=method password

=cut
