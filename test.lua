local sha1 = require( 'hash' );

local hash = sha1();
hash:feed( 'abc' );
hash:finish();

print( hash:result_hex() );
