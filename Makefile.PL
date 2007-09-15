# Load the Module::Install bundled in ./inc/
use inc::Module::Install;

# Define metadata
name           'IO-Socket-Telnet';
all_from       'lib/IO/Socket/Telnet.pm';

requires       'IO::Socket::INET';
requires       'parent';
requires       'Class::Method::Modifiers';

build_requires 'Test::More';

auto_install;
WriteAll;

