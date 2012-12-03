#!/usr/bin/env VERSIONER_PERL_PREFER_32_BIT=yes /usr/bin/perl
# (C) 2009-2011 Dave Vasilevsky <dave@vasilevsky.ca>
# Licensing: Simplified BSD License, see LICENSE file
use warnings;
use strict;

use Mac::Memory;
use Mac::Resources;

use File::Find;
use Getopt::Long;
use Pod::Usage;
use Fcntl qw(:seek);

sub machCPU {
    my $i = shift;
    my @types = (undef, 'VAX', (undef) x 4, '68k', 'x86', 'MIPS', undef,
        'm98k', 'HPPA', 'ARM', 'm88k', 'Sparc', 'i860', 'Alpha',
        undef, 'PowerPC');
    my %m64types = (7 => 'AMD64', 18 => 'PPC64');
    
    my $idx = $i & 0x00ffffff;
    my $m64 = $i & 0x01000000;
    my $cpu = $m64 ? $m64types{$idx} : $types[$idx];
    return undef unless $cpu;
    
    return { format => 'Mach-O', cpu => $cpu, bits => $m64 ? 64 : 32 };
}

sub machEndian {
    my $tmpl = shift;
    return $tmpl eq 'N' ? 'big' : 'little';
}

sub machFat {
    my ($df, $tmpl) = @_;
    read($df, my $count, 4) == 4 or return;
    $count = unpack($tmpl, $count);
    
    # Distinguish from Java class files
    return if $count >= 40;
    
    my @types;
    for my $i (0...$count-1) {
        read($df, my $data, 20) == 20 or return;
        my $cpu = unpack($tmpl, substr($data, 0, 4));
        my $cpudesc = machCPU($cpu);
        push @types, $cpudesc if $cpudesc;
    }
    return @types;
}

sub magic {
	my ($path, $len) = @_;
	open my $fh, '<', $path or return undef;
	my $readlen = read($fh, my $magic, $len);
	return ($fh, $magic);
}

sub machType {
    my ($df, $magic) = @_;
    return undef unless length($magic) >= 4;
    substr($magic, 4) = '';

	my ($tmpl, $fat);
    for my $t ('N', 'V') {
        my $i = unpack($t, $magic);
        $fat = 1 if $i == 0xcafebabe;
        $fat = 0 if $i == 0xfeedface || $i == 0xfeedfacf;
        if (defined $fat) {
            $tmpl = $t;
            last;
        }
    }
    return undef unless defined $fat;
    
    my @types;
	seek $df, 4, SEEK_SET;
    if ($fat) {
        @types = machFat($df, $tmpl);
    } elsif (defined $fat) {
        my $readlen = read($df, my $cpu, 4);
        if ($readlen == 4) {
            @types = machCPU(unpack($tmpl, $cpu));
        }
    }
    return undef unless @types;
    
    my %exec = (types => \@types,
        macho => { endian => machEndian($tmpl), fat => $fat }
    );
    return \%exec;
}

sub cfrgType {
    my $res = shift;
    my @types;
    my %cpus = (pwpc => 'PowerPC', m68k => 'm68k');
    
    my $data = $res->get();
    return unless length($data) >= 32;
    my $count = unpack('N', substr($data, 28, 4));
    
    my $pos = 32;
    for my $i (0..$count-1) {
        return unless length($data) >= $pos + 42;
        my $size = unpack('n', substr($data, $pos + 40, 2));
        
        my $cpuid = substr($data, $pos, 4);
        my $fragtype = unpack('C', substr($data, $pos + 22, 1));
        if ($fragtype == 1) {
            return unless exists $cpus{$cpuid};
            push @types, { format => 'CFM', cpu => $cpus{$cpuid}, bits => 32 };
        }
        
        $pos += $size;
    }
    
    return @types;
}

sub rsrcType {
    my $path = shift;
    my $rf = FSpOpenResFile($path, 0) or return;
    my @types;
    
    if (GetResource('CODE', 0)) {
        push @types, { format => 'CODE', cpu => '68k', bits => 32 };
    }
    
    if (my $res = GetResource('cfrg', 0)) {
        push @types, cfrgType($res);
    }
    
    CloseResFile($rf);
	return @types;
}

sub pefType {
	my ($fh, $magic) = @_;
	return unless substr($magic, 0, 12) eq 'Joy!peffpwpc';
	return ({ format => 'PEF', cpu => 'PowerPC', bits => 32 });
}

sub executableType {
    my $path = shift;
    
	my ($fh, $magic) = magic($path, 12);
	my $exec;
	if (defined $magic) {
		$exec = machType($fh, $magic);
		unless ($exec) {
			my @types = (rsrcType($path), pefType($fh, $magic));
			$exec = @types ? { types => \@types } : undef;
		}
	}
	close $fh if $fh;
    return $exec;
}

# New apps should include Mach-O x86 or Mach-O AMD64
sub newExecType {
    my $exec = shift;
    my %okcpu = map { $_ => 1 } qw(x86 AMD64 ARM); 
    return grep { $_->{format} eq 'Mach-O' && $okcpu{$_->{cpu}} } @{$exec->{types}};
}

sub dumpObj {
    my $exec = shift;
    my $prefix = shift || '';
#use Data::Dumper; print Dumper $exec;

    if (my $detail = $exec->{macho}) {
        my @d = ();
        push @d, 'FAT' if $detail->{fat};
        push @d, sprintf("%s endian", ucfirst $detail->{endian});
        print $prefix, join(', ', @d), "\n";
    }
    
    foreach my $type (@{$exec->{types}}) {
        printf "%s%s %s\n", $prefix, @$type{qw/format cpu/};
    }
}

sub dumpPath {
    my $path = shift;
    
    my $exec = executableType($path);
    if ($exec) {
        dumpObj($exec);
    } else {
        print "Not an executable!\n";
    }    
}

sub findPred {
    my $pred = shift;
    find(sub {
		my ($dev) = lstat($_);
		if ($File::Find::topdev != $dev) {
			$File::Find::prune = 1;
			return;
		}
		return unless -f _;
		
		my $exec = executableType($_) or return;
        return unless $pred->($exec);
        print "$File::Find::name\n";
        dumpObj($exec, "   ");
    }, @_);
}

=head1 NAME

  appFormat.pl - Find the format of Mac apps
  
=head1 SYNOPSIS

  appFormat.pl [options] [path ...]
  
  Options:
    -o, --old       Find only old apps
    -h, --help      Print this message

=cut

my $pred = sub { 1 }; # TRUE
my $help = 0;
GetOptions(
    'old' => sub { $pred = sub { !newExecType(@_) } },
    'help' => \$help) or pod2usage(2);
pod2usage(1) if $help;

my @search = @ARGV ? @ARGV : ('.');
findPred($pred, @search);
