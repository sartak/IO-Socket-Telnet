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

IO::Socket::Telnet - Transparent telnet negotiation for IO::Socket::INET

=head1 VERSION

Version 0.01 released ???

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

    use IO::Socket::Telnet;
    my $socket = IO::Socket::Telnet->new(PeerAddr => 'random.server.org',
                                         PeerPort => 23);
    while (1) {
        $socket->send(scalar <>);
        defined $socket->recv(my $x, 4096) or die $!;
    }

=head1 DESCRIPTION

Telnet is a simple protocol that sits on top of TCP/IP. It handles the
negotiation of various options, both about the connection itself (ECHO)
and the setup of both sides of the party (NAWS, TTYPE).

This is a wrapper around L<IO::Socket::INET> that both strips out the telnet
escape sequences and lets you handle the negotiation in a high-level manner.

The interface for defining callbacks is subject to change. It needs to be
less manual.

=head1 CAVEATS

You must use the C<< $socket->recv(...) >> method call form.
C<recv($socket, ...)> will not invoke the necessary methods. You can use
C<print $socket ...> because C<print> currently has no special semantics.

=head1 SIMILAR MODULES

L<Net::Telnet> has a similar purpose, to interact via telnet with someone else.
The major difference is that L<Net::Telnet> tries to be L<Expect> to some
degree as well. This is fine if that's what you need to do, but the author of
L<IO::Socket::Telnet> wants to play NetHack on a remote server, and
L<Net::Telnet> doesn't help him very much.

=head1 SEE ALSO

L<Net::Telnet>, L<IO::Socket::INET>, L<IO::Socket>, L<IO::Handle>

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

