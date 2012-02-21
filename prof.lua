
local sha1 = require( 'hash' );


local data = string.rep( 'a', 1000 );
local average, min, max;

for round = 1, 100 do
    local start = os.clock();
    local hash = sha1();

    for idx = 1, 1000 do
        hash:feed( data );
    end

    hash:finish();

    local elapsed = os.clock() - start;
    if nil == average then
        average, min, max = elapsed, elapsed, elapsed;
    else
        average = (average + elapsed) / 2;
        if elapsed < min then min = elapsed end
        if elapsed > max then max = elapsed end
    end
end

print( string.format(
    "average: %.3fs, min: %.3fs, max: %.3fs", average, min, max ) );

