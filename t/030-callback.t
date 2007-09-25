#!perl -T
use strict;
use warnings;
use Test::More tests => 18;
use IO::Socket::Telnet;

my @sent;
{
    no warnings 'once';
    *IO::Socket::Telnet::send = sub
    {
        my ($self, $text) = @_;
        push @sent, $text;
    };
}

my $seen = 0;
my $socket = IO::Socket::Telnet->new();
$socket->telnet_simple_callback(sub { ++$seen; return });

my $IAC = chr(255);
my $WONT = chr(252);
my $DO = chr(253);
my $ECHO = chr(1);

is($socket->_parse("$IAC$DO$ECHO"), '', "IAC DO ECHO parsed out");
is($seen, 1, "callback called");
ok(@sent, "some kind of response was sent");
is(pop @sent, "$IAC$WONT$ECHO", "default response of IAC WONT ECHO");

