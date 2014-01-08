# NAME

Net::Salesforce - Authentication against Salesforce OAuth 2 endpoints.

# SYNOPSIS

    use Net::Salesforce;

    my $sf = Net::Salesforce->new(
        'key'          => $ENV{SFKEY},
        'secret'       => $ENV{SFSECRET},
        'redirect_uri' => 'https://localhost:8081/callback'
    );

# DESCRIPTION

Net::Salesforce is an authentication module for Salesforce OAuth 2.

# ATTRIBUTES

## authorize\_url

## key

## params

## password

## redirect\_uri

## response\_type

## scope

## secret

## ua

A [Mojo::UserAgent](https://metacpan.org/pod/Mojo::UserAgent) object.

## json

A [Mojo::JSON](https://metacpan.org/pod/Mojo::JSON) object.

# METHODS

## verify\_signature

## refresh

## oauth2

## access\_token\_url

## authenticate

# AUTHOR

Adam Stokes <adamjs@cpan.org>

# COPYRIGHT

Copyright 2014- Adam Stokes

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# SEE ALSO
