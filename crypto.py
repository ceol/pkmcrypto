#!/usr/bin/python

"""Cryptography for Pokemon

This module implements the Pokemon PRNG and pkm encryption algorithms.
This can both be called from the command line and imported for use
in other projects.  While this code is intended as a learning tool,
it is the author's intent that users of this code use it responsibly.
At best, this current implementation allows others to verify
Pokesav-decrypted pkm files against encrypted save file data and to
play with the PRNG.

tl;dr: This code, as it is, is mostly harmless.

The PRNG is implemented as the "prng" class.  For an overview, you can
do the following from the Python interactive shell:
    >> import crypto
    >> print crypto.prng.__doc__

pkm encryption is implemented in two separate functions; to use those,
either consult the source or list their docstrings:
    >> import crypto
    >> print crypto.decode.__doc__
    >> print crypto.encode.__doc__
"""

__author__ = "Stephen Anthony Uy <tsanth@iname.com>"

from array import array
from random import randint
from struct import unpack, pack
from sys import stdout

# Psyco yields a significant speedup.
try:
    import psyco
    psyco.full()
    pass
except ImportError:
    pass

#
# START class prng
#

class prng( object ):
    """Implements the 3rd- and 4th-gen Pokemon pseudorandom number generator.

    The Pokemon PRNG is a linear congruential generator.  The PRNG
    is used most notably for generating Pokemon personality values (PVs) and
    individual values (IVs).  Given an implementation of the PRNG which allows
    one to run the PRNG backwards (as this does), it is possible to
    generate PV-IV combinations which are legally possibly in the game.
    The implications of this are left for the reader to derive.

    Examples of usage:

    >>> print "%08x" % (prng.seed( 0 ))
    00000000

    >>> print "%08x" % (prng.prevSeed())
    0a3561a1

    >>> print "%08x" % (prng.rand())
    00000000

    >>> print "%08x" % (prng.rand())
    0000e97e

    >>> print "%08x" % (prng.seed( 0xFFFFFFFF ))
    ffffffff

    >>> print "%08x" % (prng.prevSeed())
    1b7b763c

    >>> print "%08x" % (prng.rand())
    0000be3a

    >>> print "%08x" % (prng.rand())
    000026db
    """


    # These are the constants for the PRNG.
    #
    # Note that an LCG is a random number generator of the form:
    #    X[n+1] = (a * X[n] + c) % m
    #
    # For the Pokemon PRNG, we have these values:
    #    a = 0x41C64E6D
    #    c = 0x6073
    #    m = 0xFFFFFFFF
    RANDOMIZER = 0x41C64E6D
    OFFSET = 0x6073
    SEEDMASK = 0xFFFFFFFF

    # This is the modular inverse used for running the LCG backwards.
    #
    # Of particular note is the O(1) implementation of deriving
    # the previous random number: that implementation uses the modular
    # inverse of our multiplicative constant:
    #    a^(-1) = 0xEEB9EB65.
    INVERSERANDOMIZER = 0xEEB9EB65

    # This is the modular inverse of the additive constant.
    #
    # This is used in the Shoddy validator code, but isn't strictly
    # necessary for the LCG to run backwards (I think).
    # This has been tested on corner cases of 0x00000000 and 0xFFFFFFFF.
    INVERSEOFFSET = 0x0A3561A1

    # This constrains the PRNG output to a 16-bit number.
    RANDWIDTH = 0x10

    # This persists the random number seed throughout the PRNG's lifetime.
    #
    # Successive calls to the PRNG should return numbers in sequence;
    # the period of the entire PRNG should be 2^31 steps, given that
    # our LCG uses the ANSI C multiplicative constant for its
    # dirty work.
    #
    # References:
    # * http://en.wikipedia.org/wiki/Linear_congruential_generator
    # * http://www.foo.be/docs/tpj/issues/vol2_2/tpj0202-0008.html
    __seed = 0

    def __init__( self, seed=None ):
        """This is just standard initialization code.

        Standard initialization stuff; of particular note
        is that we generate a random number in the
        closed interval [0, SEEDMASK]; for most purposes,
        this should return something in the closed
        interval [0, 0xFFFFFFFF]
        """
        if seed is None:
            self.__seed = randint( 0, self.SEEDMASK )
        else:
            self.__seed = seed
        pass

    def seed( self, newSeed=None ):
        """Returns the current random number seed.

        If called without a parameter, returns the current
        seed; if called with a parameter, sets the seed
        to the parameter and returns that parameter.

        >>> print "%08x" % (prng.seed( 0xCAFEBABE ))
        cafebabe

        >>> print "%08x" % (prng.seed())
        cafebabe
        """
        if newSeed is not None:
            self.__seed = newSeed
        return self.__seed

    def prevSeed( self, curSeed=None ):
        """Returns the previous random number seed.

        If called without a parameter, returns the seed previous
        to the current one; if called with a parameter, it
        calculates the previous seed relative to that parameter.
        Calling this with a parameter does not change the
        currently-stored seed.

        >>> print "%08x" % (prng.prevSeed( 0xCAFEBABE ))
        8d6f7897

        >>> print "%08x" % (prng.seed( 0xB84FC759 ))
        b84fc759

        >>> print "%08x" % (prng.prevSeed())
        cafebabe
        """
        if curSeed is None:
            lastSeed = self.__seed
        else:
            lastSeed = curSeed
        lastSeed -= self.OFFSET
        lastSeed &= self.SEEDMASK
        lastSeed *= self.INVERSERANDOMIZER
        lastSeed &= self.SEEDMASK
        return lastSeed

    def rand( self ):
        """Returns the next random number.

        The returned number will by RANDWIDTH bits wide.
        Typically, this will be 0x10 bits (16 bits).

        >>> print "%08x" % (prng.seed( 0x8D6F7897 ))
        8d6f7897

        >>> print "%08x" % (prng.rand())
        0000cafe

        >>> print "%08x" % (prng.seed())
        cafebabe

        >>> print "%08x" % (prng.rand())
        0000b84f

        >>> print "%08x" % (prng.seed())
        b84fc759
        """
        self.__seed *= self.RANDOMIZER
        self.__seed &= self.SEEDMASK
        self.__seed += self.OFFSET
        self.__seed &= self.SEEDMASK
        return self.__seed >> self.RANDWIDTH

    def prevRand( self, newSeed=None ):
        """Returns the previous random number.

        If called without a parameter, returns the previous
        random number based upon the current seed; if called
        with a parameter, returns the previous random number
        based upon the parameter.  As is the case with prevSeed(),
        calling this with a parameter does not change the
        currently-stored seed.

        The returned number will be RANDWIDTH bits wide.
        Typically, this will be 0x10 bits (16 bits).

        >>> print "%08x" % (prng.seed( 0xB84FC759 ))
        b84fc759

        >>> print "%08x" % (prng.prevRand())
        0000cafe

        >>> print "%08x" % (prng.seed())
        cafebabe

        >>> print "%08x" % (prng.prevRand())
        00008d6f

        >>> print "%08x" % (prng.seed())
        8d6f7897
        """
        if newSeed is None:
            self.__seed = self.prevSeed()
        else:
            self.__seed = self.prevSeed( newSeed )
        return self.__seed >> self.RANDWIDTH

#
# END class prng
#

#
# START pkm encryption functions
#

def _checksum( data ):
    """Calculates the checksum for a given data block.

    Expects a string of data.
    Returns a 16-bit checksum.

    Note: The pokemon data is normally 128 bytes long.
          If longer or shorter data blocks are passed in,
          this function will still calculate the checksum.
    """
    # The checksum is calculated using 16-bit values.
    data = array( "H", data.tostring() )

    # Simple checksum: add the value of each data word.
    checksum = 0
    for word in data:
        checksum += word

    # Truncate the checksum to 16 bits.
    checksum &= 0xFFFF
    return checksum

def _crypt( data, expectedChecksum=None ):
    """Encrypts the given data with the given key.

    If called with an expected 16-bit checksum, the function will assume
    that the data is to be decrypted; if no checksum is given, the
    function will assume that the data is to be encrypted.

    Expects a string of data and the optional expected 16-bit checksum.
    Returns a tuple:
        1) A string, and
        2) The calculated checksum.
    Raises a ValueError if the calculated checksum doesn't match
    the expected checksum.
    """
    # Encryption works with 16-bit words.
    data = array( "H", data )

    # If we're not given an expected checksum, assume we're encrypting
    # and calculate the checksum for the given data.
    # Otherwise, assume we're decrypting and use the expected checksum
    # as the decryption key.
    if expectedChecksum is None:
        key = _checksum( data )
    else:
        key = expectedChecksum

    # Decrypt/encrypt data and calculate checksum simultaneously.
    p = prng( key )
    decData = array( "H" )
    checksum = 0
    for word in data:
        decWord = word ^ p.rand()   # Yes, it really is this easy.
        decData.append( decWord )
        checksum += decWord

    # The checksum is always truncated to 16 bits.
    checksum &= 0xFFFF

    # If we were decrypting, verify the checksum.
    if expectedChecksum is not None and expectedChecksum != checksum:
        raise ValueError( "Decryption error: expected checksum " +
                          "0x%04x, but got 0x%04x" % (expectedChecksum,
                                                      checksum) )

    # If we were encrypting, our checksum is our key.
    if expectedChecksum is None:
        checksum = key

    return (decData.tostring(), checksum)

def _reorderBlocks( pv, data ):
    """Reorders the pokemon data according to the PV.

    Expects a 32-bit PV and a 128-byte string.
    Returns a 128-byte string.
    Raises a ValueError if the data is not 128 bytes long.
    """
    # Data should be 128 bytes long.
    if len( data ) != 128:
        raise ValueError( "Cannot reorder blocks: must have 128 bytes " +
                          "(got %d bytes)" % (len( data )) )

    # 128 bytes of data is split into four 32-byte blocks.
    blocks = [
        data[0x00:0x20],
        data[0x20:0x40],
        data[0x40:0x60],
        data[0x60:0x80] ]

    # The PV tells us how to shift the blocks.
    shiftVal = ((pv >> 0xD) & 0x1F) % 24

    # The blocks are shifted in an ascending permutation.  To wit:
    #   00 = ABCD   01 = ABDC   02 = ACBD   03 = ACDB
    #   04 = ADBC   05 = ADCB   06 = BACD   07 = BADC
    #   08 = BCAD   09 = BCDA   10 = BDAC   11 = BDCA
    #   12 = CABD   13 = CADB   14 = CBAD   15 = CBDA
    #   16 = CDAB   17 = CDBA   18 = DABC   19 = DACB
    #   20 = DBAC   21 = DBCA   22 = DCAB   23 = DCBA
    #
    # Given a list [ 'A', 'B', 'C', 'D' ], we can calculate which elements
    # to pop out to yield the correct order, e.g.:
    #   pop #1 (shiftVal / 6):
    #       0 = A (BCD)
    #       1 = B (ACD)
    #       2 = C (ABD)
    #       3 = D (ABC)
    #
    #   pop #2 ((shiftVal % 6) / 2):
    #       0 = first
    #       1 = second
    #       2 = third
    #
    #   pop #3 ((shiftVal % 6) % 2)):
    #       0 = first
    #       1 = second
    #
    #   pop #4 is always the remaining element.
    #
    # Yes, this might be inefficient, but it sure _looks_ arcane!
    whichBlock = [
        shiftVal / 6,
        (shiftVal % 6) / 2,
        (shiftVal % 6) % 2,
        0 ]

    # Blocks are reordered according to the PV.
    reorderedBlocks = []
    for index in whichBlock:
        reorderedBlocks.append( blocks.pop( index ) )
    reorderedBlocks = "".join( reorderedBlocks )

    return reorderedBlocks

def _unpackPkm( pkm ):
    """Breaks up pkm data into the PV, checksum, and data.

    Expects a 136-byte string representing the pkm data.
    Returns a tuple:
        1) The 32-bit PV,
        2) The 16-bit checksum, and
        3) The 128-byte data.
    Raises a ValueError if the pkm data is not 136 bytes long.
    """
    # Encrypted pkm data should be 136 bytes long.
    if len( pkm ) != 136:
        raise ValueError( "Cannot unpack pkm: must be 136 bytes " +
                          "(got %d bytes)" % (len( pkm )) )

    # The PV is the first four bytes.
    pv = unpack( "I", pkm[ 0x00:0x04 ] )[ 0 ]

    # Skip two bytes, then the checksum is the next two bytes.
    checksum = unpack( "H", pkm[ 0x06:0x08 ] )[ 0 ]

    # The data is in the remaining bytes.
    data = pkm[ 0x08:0x88 ]

    return (pv, checksum, data)

def decode( pkm ):
    """Decrypts and unshuffles pkm data.

    Expects a string containing the encrypted pkm data.
    Encrypted data is expected to be 136 bytes long.
    Returns a tuple:
        1) The 32-bit PV,
        2) The 16-bit checksum, and
        3) The 128-byte data string.

    E.g.:
        >> (pv, checksum, data) = decode( open( "foo.pkm", "rb" ).read() )
    """

    # Break the pkm into its parts.
    (pv, checksum, data) = _unpackPkm( pkm )

    # Decoding happens in two stages:
    #   1) Decryption, and
    #   2) Reordering blocks.
    # Decryption will raise an exception if the expected
    # checksum does not match the calculated checksum.
    (data, checksum) = _crypt( data, checksum )
    data = _reorderBlocks( pv, data )

    return (pv, checksum, data)

def _packPkm( pv, checksum, data ):
    """Given a PV, checksum, and pokemon data, creates a pkm string.

    Expects a 32-bit PV, 16-bit checksum, and 128-byte data string.
    Returns a 136-byte string representing the pkm file.
    Raises a ValueError if the data is not 128 bytes long.
    """
    # Pokemon data-proper should be 128 bytes long.
    if len( data ) != 128:
        raise ValueError( "Cannot pack data into pkm: must be 128 bytes " +
                          "(got %d bytes)" % (len( pkm )) )

    # Put all the parts together.
    pkmContent = [
        pack( "I", pv ),
        "\00\00",
        pack( "H", checksum ),
        data ]
    pkm = "".join( pkmContent )

    return pkm

def encode( pv, data ):
    """Shuffles and encrypts pkm data.

    Expects a 32-bit PV and cleartext pkm data.
    Cleartext pkm data is expected to be 128 bytes long.
    Returns a string containing the encoded data, 136 bytes long.

    E.g.:
        >> outdata = encode( pv, data )
    """
    # Encoding happens in two stages:
    #   1) Reordering blocks, and
    #   2) Encryption.
    data = _reorderBlocks( pv, data )
    (encData, checksum) = _crypt( data )

    # At this point, we have our 136-byte encrypted pkm file.
    return _packPkm( pv, checksum, encData )

#
# END pkm encryption functions
#

#
# START tests
#

def _testPrng():
    """Runs the PRNG doctests.

    The tests use the following known sequence of numbers
    generated by the Pokemon PRNG:
        0x8D6F7897 -> 0xCAFEBABE -> 0xB84FC759
    """
    print "Running PRNG tests..."
    import doctest
    testGlobals = {
        "prng" : prng(),
    }
    doctest.testmod( globs=testGlobals )
    print "-- PRNG tests complete!"
    pass

def _testPkm():
    """Runs the pkm encryption tests.

    Uses the files clyde_enc.pkm and clyde_dec.pkm to perform some tests:
        * Perform a test decryption
        * Verify decryption output
        * Perform a test encryption
        * Verify encryption output
    """
    print "Running pkm tests..."
    # Read test data
    encData = open( "clyde_enc.pkm", "rb" ).read()
    decData = open( "clyde_dec.pkm", "rb" ).read()

    # Perform decryption
    (pv, checksum, data) = decode( encData )
    decPkm = _packPkm( pv, checksum, data )

    # Verify decryption
    for idx in range( 0x00, 0x88 ):
        if decData[ idx ] != decPkm[ idx ]:
            raise ValueError( "Decryption mangled at index %d!" % (idx) )

    # Perform encryption
    encPkm = encode( pv, data )

    # Verify encryption
    for idx in range( 0x00, 0x88 ):
        if encData[ idx ] != encPkm[ idx ]:
            raise ValueError( "Encryption mangled at index %d!" % (idx) )
    print "-- pkm tests complete!"

def _runTests( option, opt_str, value, parser ):
    """Runs both PRNG and encryption tests.
    """
    print "Running tests..."
    _testPrng()
    _testPkm()
    print "All tests complete!"
    exit( 0 )

#
# END tests
#

if __name__ == "__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option( "-d", "--decrypt", action="store_true", dest="decrypt",
                       default=False, help="Perform decryption (default)" )
    parser.add_option( "-e", "--encrypt", action="store_true", dest="encrypt",
                       default=False, help="Perform encryption" )
    parser.add_option( "-i", "--infile", dest="infile",
                       metavar="INFILE", help="Input file" )
    parser.add_option( "-o", "--outfile", dest="outfile",
                       metavar="OUTFILE",
                       help="Output file (default: out.pkm)" )
    parser.add_option( "-t", "--test", action="callback", callback=_runTests,
                       help="Run verification tests" )
    (options, args) = parser.parse_args()
    if options.infile is None:
        parser.print_help()
        exit( 2 )
    else:
        indata = open( options.infile, "rb" ).read()
        if len( indata ) != 136:
            print "ERROR: Input file must be 136 bytes long!"
            exit( 1 )
        else:
            # Encrypt or decrypt
            if options.encrypt:
                pv = unpack( "I", indata[ 0x00:0x04 ] )[ 0 ]
                outdata = encode( pv, indata[ 0x08:0x88 ] )
            else:
                (pv, checksum, data) = decode( indata )
                outdata = _packPkm( pv, checksum, data )

            # Open output file
            if options.outfile is None:
                print "Using default output: out.pkm"
                outhandle = open( "out.pkm", "wb" )
            else:
                outhandle = open( options.outfile, "wb" )

            # Write to output
            outhandle.truncate()
            outhandle.write( outdata )
            outhandle.close()
            print "Done!"
            exit( 0 )

"""
Acknowledgments:
    * Angela for being patient while I spent hours coding all this.
    * loadingNow for providing important insight into the PRNG as well
      as a disassembly and working implementation of pkm encryption.
    * Sabresite for helping me catch a few pesky bugs and for being
      a great assistance in other code.
    * Jeffmaz2001 for being consistent and stalwart in his convictions.
    * MLBloomy for providing corrections and helping weed out logical
      inconsistencies.
    * Ice3090 for providing useful AR codes to examine.
    * The rest of the Pokemon Pearl board on GameFAQs for their support.

Copyright (c) 2008 Stephen Anthony Uy.  All rights reserved.

Originally written on Ubuntu v8.04 using vim v7.1 for Python v2.5.2.
The author holds no illusions about people actually respecting
his copyright notice, nor about how this code may be used,
but hopes that wherever this code goes, it may be of some use.



"The truth will set you free. But first, it will piss you off."
    -Gloria Steinem



v1.0
"""

