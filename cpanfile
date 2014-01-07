requires 'Digest::SHA';
requires 'Mojo::Base';
requires 'Mojo::Parameters';
requires 'Mojo::URL';
requires 'Mojo::UserAgent';

on build => sub {
    requires 'Test::More';
    requires 'Test::Pod';
    requires 'Test::Pod::Coverage';
};

on test => sub {
    requires 'Test::More';
};
