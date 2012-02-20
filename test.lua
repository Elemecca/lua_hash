local chunk, message = loadfile( 'sha-1.lua' );
if nil == chunk then
    error( 'error loading sha-1:\n' .. message );
end

local sha1 = chunk();

local hash = sha1();
hash:feed( 'abc' );
hash:finish();

print( hash:result_hex() );
