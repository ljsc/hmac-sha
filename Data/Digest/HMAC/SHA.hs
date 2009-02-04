-- | Implementation of the HMAC algorithm for SHA hash functions.
module Data.Digest.HMAC.SHA
  ( hmac_sha1
  , hmac_sha224
  , hmac_sha256
  , hmac_sha384
  , hmac_sha512
  )
where

import qualified Data.ByteString.Lazy as BS
import Data.Bits (xor)
import Data.Char (ord)
import Data.Digest.Pure.SHA (sha1, sha224, sha256, sha384, sha512,
                             bytestringDigest, showDigest, Digest)
import Data.Int (Int64)
import Text.Printf (printf)

data HashAlgorithm = HA {
  ha_f          :: (BS.ByteString -> Digest),
  ha_blockSize  :: Int64,
  ha_outputSize :: Int64
}

--
-- Generalized HMAC algorithm.
--
hmac :: HashAlgorithm -> BS.ByteString -> BS.ByteString -> String
hmac alg@(HA h bs hs) k m = showDigest outerHash
  where key       = normalizeKey alg k
        ipadK     = key `xorB` BS.replicate bs 0x36
        opadK     = key `xorB` BS.replicate bs 0x5C
        innerHash = bytestringDigest . h $ BS.append ipadK m
        outerHash = h (BS.append opadK innerHash)

--
-- Keys need to be padded out to the block size of the hashing algrithm. If they
-- are longer than the block size the key is hashed to create a new key which fits
-- into a block.
--
normalizeKey :: HashAlgorithm -> BS.ByteString -> BS.ByteString
normalizeKey alg k = padRightTo bs . f $ k
  where bs = ha_blockSize alg
        f  = if BS.length k > bs
                then bytestringDigest . (ha_f alg)
                else id

--
-- Used to right pad the key with 0 bytes up to the block size.
--
padRightTo :: Int64 -> BS.ByteString -> BS.ByteString
padRightTo size m = BS.append m (BS.replicate (size - BS.length m) 0x00)

--
-- exclusive or lifted to work on ByteStrings.
--
xorB :: BS.ByteString -> BS.ByteString -> BS.ByteString
a `xorB` b = BS.pack $ BS.zipWith xor a b

--------------------------------------------------------------------------------
-- HMAC Implementations via SHA:
--------------------------------------------------------------------------------

hmac_sha1,
  hmac_sha256, hmac_sha224,
  hmac_sha384, hmac_sha512
    :: BS.ByteString -- ^ The secret key
    -> BS.ByteString -- ^ The message to compute the hash for
    -> String        -- ^ The computed HMAC

hmac_sha1   = hmac $ HA sha1    64 20 -- ^ Compute HMAC with SHA1 algorithm
hmac_sha224 = hmac $ HA sha224  64 28 -- ^ Compute HMAC with SHA224 algorithm
hmac_sha256 = hmac $ HA sha256  64 32 -- ^ Compute HMAC with SHA256 algorithm
hmac_sha384 = hmac $ HA sha384 128 48 -- ^ Compute HMAC with SHA384 algorithm
hmac_sha512 = hmac $ HA sha512 128 64 -- ^ Compute HMAC with SHA512 algorithm

--------------------------------------------------------------------------------
-- Utils for inspecting ByteStrings as hex
--------------------------------------------------------------------------------

printHex :: BS.ByteString -> IO ()
printHex = putStr . prettyHexLns

prettyHex, prettyHexLns :: BS.ByteString -> String
prettyHex    = prettyHex' unwords
prettyHexLns = prettyHex' $ unlines . map unwords . groupN 4

prettyHex' :: ([String] -> String) -> BS.ByteString -> String
prettyHex' lnf = lnf . groupOctets . map b2hex . BS.unpack
  where b2hex n     = printf "%02x" (fromIntegral n :: Int)
        groupOctets = map concat . groupN 4

groupN :: Int -> [a] -> [[a]]
groupN n [] = []
groupN n xs = take n xs : groupN n (drop n xs)

