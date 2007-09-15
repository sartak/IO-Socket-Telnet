#!perl
package IO::Socket::Telnet;
use strict;
use warnings;
use parent 'IO::Socket::INET';
use Class::Method::Modifiers;

around new => sub
{
    my $orig = shift;
    my $self = $orig->(@_);

    ${*$self}{telnet_mode} = 'normal';
    ${*$self}{telnet_sb_buffer} = '';

    return $self;
};

after recv => sub
{
    $_[1] = $_[0]->_parse($_[1]);
};

my $IAC = chr(255);
my $SB = chr(250);
my $SE = chr(240);

my $WILL = chr(251);
my $WONT = chr(252);
my $DO = chr(253);
my $DONT = chr(254);

my %dispatch =
(
    normal => sub
    {
        my ($self, $c) = @_;
        return $c unless $c eq $IAC;
        return (undef, 'iac');
    },

    iac => sub
    {
        my ($self, $c) = @_;
        return ($IAC, 'normal') if $c eq $IAC;
        return (undef, 'do')    if $c eq $DO;
        return (undef, 'dont')  if $c eq $DONT;
        return (undef, 'will')  if $c eq $WILL;
        return (undef, 'wont')  if $c eq $WONT;
        return (undef, 'sb')    if $c eq $SB;
    },

    do => sub
    {
        my ($self, $c, $m) = @_;
        $self->_telnet_simple_callback($m, $c);
        return (undef, 'normal');
    },

    sb => sub
    {
        my ($self, $c) = @_;
        return (undef, 'sbiac') if $c eq $IAC;
        return (undef, undef, $c);
    },

    sbiac => sub
    {
        my ($self, $c) = @_;
        if ($c eq $IAC)
        {
            ${*$self}{telnet_sb_buffer} .= $IAC;
            return (undef, 'sb');
        }

        if ($c eq $SE)
        {
            $self->_telnet_complex_callback();
            ${*$self}{telnet_sb_buffer} = '';
            return (undef, 'normal');
        }

        # IAC followed by something other than IAC and SE.. what??
        require Carp;
        Carp::croak "Invalid telnet stream: IAC SE ... IAC $c";
    },
);

$dispatch{dont} = $dispatch{will} = $dispatch{wont} = $dispatch{do};

sub _parse
{
    my ($self, $in) = @_;
    my $out = '';

    C: for my $c (split '', $in)
    {
        my ($o, $m)
            = $dispatch{${*$self}{telnet_mode}}
                ->($self, $c, ${*$self}{telnet_mode});

        defined $o and $out .= $o;
        defined $m and ${*$self}{telnet_mode} = $m;
    }

    return $out;
}

sub _telnet_simple_callback
{
    my ($self, $char, $mode) = @_;
    ${*$self}{telnet_simple_cb} or return;
    ${*$self}{telnet_simple_cb}->($self, $char, $mode);
}

sub _telnet_complex_callback
{
    my ($self, $sb) = @_;
    ${*$self}{telnet_complex_cb} or return;
    ${*$self}{telnet_complex_cb}->($self, $sb);
}

=head1 NAME

IO::Socket::Telnet - ???

=head1 VERSION

Version 0.01 released ???

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

    use IO::Socket::Telnet;
    do_stuff();

=head1 DESCRIPTION



=head1 SEE ALSO

L<Foo::Bar>

=head1 AUTHOR

Shawn M Moore, C<< <sartak at gmail.com> >>

=head1 BUGS

No known bugs.

Please report any bugs through RT: email
C<bug-io-socket-telnet at rt.cpan.org>, or browse to
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=IO-Socket-Telnet>.

=head1 SUPPORT

You can find this documentation for this module with the perldoc command.

    perldoc IO::Socket::Telnet

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/IO-Socket-Telnet>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/IO-Socket-Telnet>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=IO-Socket-Telnet>

=item * Search CPAN

L<http://search.cpan.org/dist/IO-Socket-Telnet>

=back

=head1 COPYRIGHT AND LICENSE

Copyright 2007 Shawn M Moore.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;

