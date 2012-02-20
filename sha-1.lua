
local debug = false;

local limit_32 = 2^32;
local limit_64 = 2^64;

local bnot, band, bor, bxor, brol;

if nil ~= bit32 then
    bnot = bit32.bnot;
    band = bit32.band;
    bor  = bit32.bor;
    bxor = bit32.bxor;
    brol = bit32.lrotate;
else
    local status, bitlib = pcall( require, 'bit' );
    if not status then
        status, bitlib = pcall( require, 'bit.numberlua' );
        if not status then
            error( "bit32 not available and can't load BitOp or bit.numberlua" );
        end
    end

    bnot = bitlib.bnot;
    band = bitlib.band;
    bor  = bitlib.bor;
    bxor = bitlib.bxor;
    brol = bitlib.rol;
end

local function badd (left, right)
    return (left + right) % limit_32;
end

--- Packs an integer into a big-endian binary string.
-- @param {number} value the number to be backed
-- @param {number} bytes the length of the result in bytes
-- @return {string} the encoded binary string
local function pack_int (value, bytes)
    local result = '';
    for idx = 1, bytes do
        result = string.char( value % 256 ) .. result;
        value = math.floor( value / 256 );
    end
    return result;
end

--- Unpacks an integer from a big-endian binary string.
-- @param {string} value the string from which to unpack the integer
-- @param {number} start the offset of the integer in the input string
-- @param {number} bytes the length of the integer in bytes
-- @return {number} the decoded integer value
local function unpack_int (value, start, bytes)
    local result = 0;
    for round = 0, bytes - 1 do
        result = result * 0x100 + value:byte( start + round );
    end
    return result;
end

local hashes_single = {};
local hashes_chunked = {};

------------------------------------------------------------------------
-- Algorithm: SHA-1                                                   -- 
-- specified in FIPS publication 180-1 (1995-04-17)                   --
-- http://www.itl.nist.gov/fipspubs/fip180-1.htm                      --
------------------------------------------------------------------------
-- This implementation is dependent on byte order within an integer and
-- thus will only behave correctly on little-endian platforms.

local sha1 = {};
sha1.__index = sha1;

function sha1_new()
    local this = {};
    setmetatable( this, sha1 );

    this[ 'H0' ] = 0x67452301;
    this[ 'H1' ] = 0xEFCDAB89;
    this[ 'H2' ] = 0x98BADCFE;
    this[ 'H3' ] = 0x10325476;
    this[ 'H4' ] = 0xC3D2E1F0;
    this[ 'length' ] = 0;

    return this;
end

local function sha1_block (self, block)
    if debug then print( "start block" ); end

    local W00, W01, W02, W03, W04, W05, W06, W07,
            W08, W09, W10, W11, W12, W13, W14, W15;
    local A = self[ 'H0' ];
    local B = self[ 'H1' ];
    local C = self[ 'H2' ];
    local D = self[ 'H3' ];
    local E = self[ 'H4' ];

    for t = 0, 79 do
        if t < 16 then
            W15 = unpack_int( block, t * 4 + 1, 4 );
        else
            W15 = brol( bxor( bxor( bxor( W12, W07 ), W01 ), W15 ), 1 );
        end

        local f, K;
        if t <= 19 then
            f = bor( band( B, C ), band( bnot( B ), D ) );
            K = 0x5A827999;
        elseif t <= 39 then
            f = bxor( bxor( B, C ), D );
            K = 0x6ED9EBA1;
        elseif t <= 59 then
            f = bor( bor( band( B, C ), band( B, D ) ), band( C, D ) );
            K = 0x8F1BBCDC;
        else
            f = bxor( bxor( B, C ), D );
            K = 0xCA62C1D6;
        end

        local temp = badd( badd( badd( badd( brol( A, 5 ), f ), E ), W15 ), K );
        E = D; D = C; C = brol( B, 30 ); B = A; A = temp;

        -- rotate the W-queue left one
        W00, W01, W02, W03, W04, W05, W06, W07,
                W08, W09, W10, W11, W12, W13, W14, W15
            = W01, W02, W03, W04, W05, W06, W07, W08,
                W09, W10, W11, W12, W13, W14, W15, W00;

        if debug then print( string.format(
            "t = %2d: %08X    %08X    %08X    %08X    %08X",
            t, A, B, C, D, E ) );
        end
    end

    self[ 'H0' ] = badd( self[ 'H0' ], A );
    self[ 'H1' ] = badd( self[ 'H1' ], B );
    self[ 'H2' ] = badd( self[ 'H2' ], C );
    self[ 'H3' ] = badd( self[ 'H3' ], D );
    self[ 'H4' ] = badd( self[ 'H4' ], E );
end

function sha1:feed (chunk)
    local length = #chunk;
    self[ 'length' ] = self[ 'length' ] + length;
    local index = 1;
    
    -- if there are leftovers from the previous call, integrate them
    local hold = self[ 'hold' ];
    if nil ~= hold then
        index = 64 - #hold;

        -- if we don't have a complete block even with the current
        -- chunk then append it to the hold buffer and return
        if length < index then
            self[ 'hold' ] = hold .. chunk;
            return;
        end

        sha1_block( self, hold .. string.sub( chunk, 1, index ) );
        self[ 'hold' ] = nil;
        index = index + 1;
    end

    while index + 63 <= length do
        sha1_block( self, string.sub( chunk, index, index + 63 ) );
        index = index + 64;
    end

    -- if we have a partial block left over store it in the hold buffer
    if index <= length then
        self[ 'hold' ] = string.sub( chunk, index );
    end
end

function sha1:finish()
    local hold = self[ 'hold' ];
    if nil == hold then hold = '' end

    -- append the first byte of padding, which is 1000 0000
    -- hold can't be a full block, so it's always safe to do this
    hold = hold .. '\128';

    -- pack the data length in bits into a 64-bit binary integer
    local length = pack_int( self[ 'length' ] * 8, 8 );

    -- if we can't fit the leftover data and the length into a single
    -- block, pad out the leftovers to a full block and process them
    if #hold > 56 then
        sha1_block( self, hold .. string.rep( '\0', 64 - #hold ) );
        hold = '';
    end

    sha1_block( self, hold .. string.rep( '\0', 56 - #hold ) .. length );
end

function sha1:result()
    return pack_int( self[ 'H0' ], 4 ) .. pack_int( self[ 'H1' ], 4 )
        .. pack_int( self[ 'H2' ], 4 ) .. pack_int( self[ 'H3' ], 4 )
        .. pack_int( self[ 'H4' ], 4 );
end

function sha1:result_hex()
    return string.format( '%08x%08x%08x%08x%08x', self[ 'H0' ],
            self[ 'H1' ], self[ 'H2' ], self[ 'H3' ], self[ 'H4' ] );
end

local function compute_sha1 (message)
    local length = #message;

    -- The message padding format isn't defined for messages longer than
    -- 2^64 bytes. It shouldn't be possible to fit a message that long
    -- into memory, but checking doesn't hurt anything.
    if length >= limit_64 then
        error( 1, "SHA-1 is not defined for messages longer than 2^64 bytes" );
    end
end

return sha1_new;
