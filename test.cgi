#!/usr/bin/perl

print "Content-type: text/plain; charset=iso-8859-1\n\n";

foreach(sort(keys(%ENV))) {
	if ( m/X_SAMPLE_LOGIN_USER_NAME/ ) {
		printf("#\n#\n[%s] = [%s]\n#\n#\n", $_, $ENV{$_});
	} else {
		printf("[%s] = [%s]\n", $_, $ENV{$_});
	}
}

