{-# LANGUAGE ForeignFunctionInterface #-}

module BACnet where

import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable
import Foreign.Marshal.Alloc

-- C-compatible BACnet address structure
data CBACnetAddress = CBACnetAddress
    { macLen :: CUChar
    , mac :: [CUChar]
    , net :: CUShort
    , len :: CUChar
    , adr :: [CUChar]
    } deriving (Show)

instance Storable CBACnetAddress where
    sizeOf _ = 2 + 7 + 2 + 1 + 7  -- Corresponds to the C struct size
    alignment _ = 2
    peek ptr = do
        macLen' <- peekByteOff ptr 0
        mac' <- mapM (peekByteOff ptr) [1..7]
        net' <- peekByteOff ptr 8
        len' <- peekByteOff ptr 10
        adr' <- mapM (peekByteOff ptr) [11..17]
        return $ CBACnetAddress macLen' mac' net' len' adr'
    poke ptr (CBACnetAddress macLen' mac' net' len' adr') = do
        pokeByteOff ptr 0 macLen'
        zipWithM_ (pokeByteOff ptr) [1..7] mac'
        pokeByteOff ptr 8 net'
        pokeByteOff ptr 10 len'
        zipWithM_ (pokeByteOff ptr) [11..17] adr'

-- C-compatible BACnet object ID structure
data CBACnetObjectId = CBACnetObjectId
    { objectType :: CInt
    , instance' :: CUInt
    } deriving (Show)

instance Storable CBACnetObjectId where
    sizeOf _ = 8  -- Corresponds to the C struct size
    alignment _ = 4
    peek ptr = do
        type' <- peekByteOff ptr 0
        inst' <- peekByteOff ptr 4
        return $ CBACnetObjectId type' inst'
    poke ptr (CBACnetObjectId type' inst') = do
        pokeByteOff ptr 0 type'
        pokeByteOff ptr 4 inst'

-- Foreign function import for whois_request_encode
foreign import ccall "whois_request_encode" 
    c_whois_request_encode :: Ptr CUChar -> CInt -> CInt -> CInt

-- High-level Haskell function to send a Who-Is request
sendWhoIs :: CInt -> CInt -> IO [CUChar]
sendWhoIs lowLimit highLimit = do
    allocaBytes 1024 $ \p -> do
        len <- c_whois_request_encode p lowLimit highLimit
        peekArray (fromIntegral len) p
