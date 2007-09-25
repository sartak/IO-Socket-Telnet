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

sub telnet_simple_callback
{
    my $self = shift;
    ${*$self}{telnet_simple_cb} = $_[0] if @_;
    ${*$self}{telnet_simple_cb};
}

sub telnet_complex_callback
{
    my $self = shift;
    ${*$self}{telnet_complex_cb} = $_[0] if @_;
    ${*$self}{telnet_complex_cb};
}

our @options = qw(BINARY ECHO RCP SGA NAMS STATUS TM RCTE NAOL NAOP NAOCRD
                  NAOHTS NAOHTD NAOFFD NAOVTS NAOVTD NAOLFD XASCII LOGOUT BM DET
                  SUPDUP SUPDUPOUTPUT SNDLOC TTYPE EOR TUID OUTMRK TTYLOC
                  VT3270REGIME X3PAD NAWS TSPEED LFLOW LINEMODE XDISPLOC
                  OLD_ENVIRON AUTHENTICATION ENCRYPT NEW_ENVIRON);

our @meta;

my $IAC  = chr(255); $meta[255] = 'IAC';
my $SB   = chr(250); $meta[250] = 'SB';
my $SE   = chr(240); $meta[240] = 'SE';

my $WILL = chr(251); $meta[251] = 'WILL';
my $WONT = chr(252); $meta[252] = 'WONT';
my $DO   = chr(253); $meta[253] = 'DO';
my $DONT = chr(254); $meta[254] = 'DONT';

our %options;
our %meta;

{
    no warnings 'uninitialized';
    @options{ @options } = 0 .. @options;
    @meta{ @meta }       = 0 .. @meta;
}

sub will
{
    my ($self, $opt) = @_;
    if (exists $options{$opt}) { $opt = $options{$opt} }
    $self->send($IAC . $WILL . $opt);
}

sub wont
{
    my ($self, $opt) = @_;
    if (exists $options{$opt}) { $opt = $options{$opt} }
    $self->send($IAC . $WONT . $opt);
}

sub do
{
    my ($self, $opt) = @_;
    if (exists $options{$opt}) { $opt = $options{$opt} }
    $self->send($IAC . $DO . $opt);
}

sub dont
{
    my ($self, $opt) = @_;
    if (exists $options{$opt}) { $opt = $options{$opt} }
    $self->send($IAC . $DONT . $opt);
}

# this is a finite state machine. each state can:
#     add some text to the output buffer
#     change to a different state
#     run other code (such as adding text to the subnegotiation buffer)

# the states are:
#     normal: every char is added to the output buffer, except IAC
#     iac:    we've received an IAC, this is the start of a command
#                 if we receive an IAC in state iac, append IAC to the output
#                 buffer and switch back to normal mode (IAC IAC is like \\)
#     do:     IAC DO OPTION: I want you to DO option
#     dont:   IAC DONT OPTION: I want you to not do this option
#     will:   IAC WILL OPTION: I WILL do this option (is this ok?)
#     wont:   IAC WONT OPTION: I WONT do this option (is this ok?)
#     sb:     IAC SB OPTION arbitrary text IAC SE
#     sbiac:  IAC received during "arbitrary text" of sb if we receive an IAC
#                 in this mode, append IAC to the subneg buffer and switch back
#                 to sb mode. if we receive an SE (subneg-end) in this mode,
#                 perform some kind of action and go back to normal mode

my %dispatch =
(
    normal => sub
    {
        my ($self, $c) = @_;
        return $c unless $c eq $IAC;
        return (undef, $IAC);
    },

    $IAC => sub
    {
        my ($self, $c) = @_;
        return ($IAC, 'normal') if $c eq $IAC;
        return (undef, $c) if $c eq $DO || $c eq $DONT
                           || $c eq $WILL || $c eq $WONT
                           || $c eq $SB;

        # IAC followed by something that we don't know about yet
        require Carp;
        Carp::croak "Invalid telnet stream: ... IAC $c (chr ".chr($c).") ...";
    },

    $DO => sub
    {
        my ($self, $c, $m) = @_;
        $self->_telnet_simple_callback($m, $c);
        return (undef, 'normal');
    },

    $SB => sub
    {
        my ($self, $c) = @_;
        return (undef, 'sbiac') if $c eq $IAC;
        ${*$self}{telnet_sb_buffer} .= $c;
        return;
    },

    sbiac => sub
    {
        my ($self, $c) = @_;

        if ($c eq $IAC)
        {
            ${*$self}{telnet_sb_buffer} .= $IAC;
            return (undef, $SB);
        }

        if ($c eq $SE)
        {
            $self->_telnet_complex_callback();
            ${*$self}{telnet_sb_buffer} = '';
            return (undef, 'normal');
        }

        # IAC followed by something other than IAC and SE.. what??
        require Carp;
        Carp::croak "Invalid telnet stream: IAC SE ... IAC $c (chr ".chr($c).") ...";
    },
);

$dispatch{$DONT} = $dispatch{$WILL} = $dispatch{$WONT} = $dispatch{$DO};

# this takes the input stream and jams it through the FSM
sub _parse
{
    my ($self, $in) = @_;
    my $out = '';

    # optimization: if we're in normal mode then we can quickly move all the
    # input up to the first IAC into the output buffer.
    if (${*$self}{telnet_mode} eq 'normal')
    {
        # if there is no IAC then we can skip telnet entirely
        $in =~ s/^([^$IAC]*)//;
        return $1 if length $in == 0;
        $out = $1;
    }

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

# called when we get a full DO/DONT/WILL/WONT
sub _telnet_simple_callback
{
    my ($self, $mode, $opt) = @_;
    my $response;

    if (${*$self}{telnet_simple_cb})
    {{
        my $wopt = ord $opt;
        $wopt = $options[$wopt] || $wopt;

        my $wmode = ord $mode;
        $wmode = $meta[$wmode] || $wmode;

        $response = ${*$self}{telnet_simple_cb}->($self, "$wmode $wopt");

        last if !defined($response);

        my $r = $response;
        $r =~ s/'//g; # just in case they said "DON'T" or "WON'T"

        if ($r eq 'DO' || $r eq 'DONT' || $r eq 'WILL' || $r eq 'WONT')
        {
            $r = chr($meta{$r});
            $response = $IAC . $r . $opt;
        }
    }}

    $response = $self->_reasonable_response($mode, $opt)
        if !defined($response);
    $self->send($response);
}

sub _reasonable_response
{
    my ($self, $mode, $opt) = @_;

       if ($mode eq $DO)   { return "$IAC$WONT$opt" }
    elsif ($mode eq $DONT) { return "$IAC$WONT$opt" }
    elsif ($mode eq $WILL) { return "$IAC$DONT$opt" }
    elsif ($mode eq $WONT) { return "$IAC$DONT$opt" }

    return "";
}

sub _telnet_complex_callback
{
    my ($self, $sb) = @_;
    ${*$self}{telnet_complex_cb} or return;
    ${*$self}{telnet_complex_cb}->($self, $sb);
}

=head1 NAME

IO::Socket::Telnet - transparent telnet negotiation for IO::Socket::INET

=head1 VERSION

Version 0.01 released 15 Sep 07

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

    use IO::Socket::Telnet;
    my $socket = IO::Socket::Telnet->new(PeerAddr => 'random.server.org',
                                         PeerPort => 23);
    while (1) {
        $socket->send(scalar <>);
        defined $socket->recv(my $x, 4096) or die $!;
        print $x;
    }

=head1 DESCRIPTION

Telnet is a simple protocol that sits on top of TCP/IP. It handles the
negotiation of various options, both about the connection itself (ECHO)
and the setup of both sides of the party (NAWS, TTYPE).

This is a wrapper around L<IO::Socket::INET> that both strips out the telnet
escape sequences and lets you handle the negotiation in a high-level manner.

There is currently no interface for defining callbacks. This will be rectified
very soon. The module as it stands is still useful for stripping out telnet
escape sequences.

This module is likely missing large parts of the telnet spec. Please let me
know if you need particular things implemented. Failing test cases are the
best bug reports!

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

