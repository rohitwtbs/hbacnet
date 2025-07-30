module Main where

import BACnet

main :: IO ()
main = do
    apdu <- sendWhoIs (-1) (-1)
    print apdu
