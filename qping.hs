-- File:        qping.hs
-- Course:      CS465 - Network Security
-- Description: Quick Ping Program

-- Sends a single icmp packet and sees if it receives anything back to quickly determine if destination host is up or not.
-- If the program hangs and nothing is returning, the host is either unreachable or something weird is happening that
-- I haven't been able to determine. Use CTRL+C or CTRL+D to exit if program hangs.

-- Issues:
-- When pinging your local host, program does not respond well and says your current host is not up.
-- Returns ICMP type 8. 

-- Command usage: "sudo ./qping host_to_ping"
-- IMPORTANT: Must run program as root user to access raw sockets
-- If you want to compile from source, just run "ghc -o qping qping.hs -outdir out" you'll need to have ghc installed.

import Data.Bits
import Data.Binary.Get
import Data.Binary.Put
import Data.Word

import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString       

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

import Control.Monad
import System.Environment (getArgs)
import System.Posix.Process (getProcessID)

-- Message types
-- Echo Reply    = 0
-- Echo          = 8
-- Source Quench = 4
-- Destination Unreachable = 3
-- Information request = 15
-- Information Reply = 16

-- In the original ping.c file, unix creates an IP packet automatically via unix kernel.
-- All we have to do is create an ICMP header instead.

{- Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
will be added on by the kernel.  The ID field is our UNIX process ID,
and the sequence number is an ascending integer.  The first 8 bytes
of the data portion are used to hold a UNIX "timeval" struct in VAX
byte-order, to compute the round-trip time -}

type ICMP_TYPE = Word8
type Code      = Word8
type CheckSum  = Word16
type Identity  = Word16
type Sequence  = Word16
type ICMP_DATA = BL.ByteString
type BLPacket  = BL.ByteString
type BPacket   = B.ByteString

echoRequest     = 8
echoReply       = 0
sourceQuench    = 4
timeExceeded    = 11
destUnreachable = 3
max_recv        = 2048  -- Max to receive to 2^11. 

-- Create an ICMP packet and put it in writer Monad
-- packet creation obtained from https://github.com/thesealion/Learning-Haskell/blob/master/ping.hs#L24
putHeader :: ICMP_TYPE -> Code -> CheckSum -> Identity -> Sequence -> ICMP_DATA -> Put
putHeader icmp_type code checksum ident seq icmp_data = do
    putWord8 icmp_type
    putWord8 code
    putWord16be checksum
    putWord16be ident
    putWord16be seq
    putLazyByteString icmp_data

-- Get header from writer monad
getHeader :: Get (ICMP_TYPE, Code, CheckSum, Identity, Sequence)
getHeader = do
    icmp_type <- getWord8
    code <- getWord8
    checksum <- getWord16be
    ident <- getWord16be
    seq <- getWord16be
    return (icmp_type, code, checksum, ident, seq)

-- This function builds a packet from an id, sequence number, and icmp data to send.
-- Also computes the checksum of the packet 
-- Obtained from https://github.com/thesealion/Learning-Haskell/blob/master/ping.hs#L24
buildPacket :: Identity -> Sequence -> ICMP_DATA -> BLPacket
buildPacket id seq icmpdata = buildPacket' $ checksum $ buildPacket' 0
    where buildPacket' chksum = runPut $ putHeader echoRequest 0 chksum id seq icmpdata

-- Resolve address info given a string hostname
resolveAddressInfo :: HostName -> IO AddrInfo
resolveAddressInfo host = liftM head $ getAddrInfo Nothing (Just host) Nothing

-- Default hints for the address family supported to find the hostname  
addrFam = defaultHints { addrFlags = [AI_NUMERICHOST], addrSocketType = Stream}

-- Calculate checksum of an ICMP packet.
-- Implementation obtained from https://github.com/thesealion/Learning-Haskell/blob/master/ping.hs#L24
-- which in turn the github user obtained it from http://programatica.cs.pdx.edu/House/
checksum :: BL.ByteString -> Word16
checksum bs = let bs' = (if (BL.length bs) `mod` 2 == 0 then bs else BL.snoc bs 0)
                  ws = runGet listOfWord16 bs'
                  total = sum (map fromIntegral ws) :: Word32
              in complement (fromIntegral total + fromIntegral (total `shiftR` 16))

-- Implementation of listOfWord16 obtained from checksum calculation source 
listOfWord16 :: Get [Word16]
listOfWord16 = do
  empty <- isEmpty
  if empty
     then return []
     else do v <- getWord16be
             rest <- listOfWord16
             return (v : rest)

printPingInfo :: String -> String -> IO ()
printPingInfo hostname ip = do
    putStrLn $ "Pinging " ++ hostname ++ " [" ++ ip ++ "] " ++ "with 32 bytes of data."

-- Command to ping
ping :: Socket -> SockAddr -> BPacket -> IO ()
ping socket dest packet = do 
    sendTo socket packet dest                                           -- Send packet to destination
    (rec_pack, senderAddress) <- recvFrom socket max_recv               -- Receive packet from destination 
    let (ipHeader, ipData) = BL.splitAt 20 (BL.fromChunks [rec_pack])   -- Parse packet, split into ipHeader and ipData
        (SockAddrInet _ otherHost) = senderAddress                      -- Make sure this destination is the one we got data from
        (icmpHeader, _) = BL.splitAt 8 ipData                           -- Split the ip data received by 8 bytes and store into icmpHeader and icmp_Data
        (icmp_type, _, _, _, _) = runGet getHeader icmpHeader           -- We only care if we got something from the destination (icmpType, code, CheckSum, IdentityRec, SequenceRec) = runGet getHeader icmpHeader
    ip <- inet_ntoa otherHost                                           -- Get ip in string format "e.g 127.0.0.1"
    checkICMPType icmp_type ip                                          -- Check the type of the icmp code we have received 
    
checkICMPType :: ICMP_TYPE -> String -> IO ()
checkICMPType icmp_t ip
    | (icmp_t == echoReply) || (icmp_t == sourceQuench) = putStrLn $ "Host " ++ ip ++ " is up!"  
    | otherwise = putStrLn $ "Host is not up." ++ " ICMP Type received: " ++ (show icmp_t) 

main :: IO ()
main = withSocketsDo $ do
    args <- getArgs                         
    pidd <- getProcessID
    if (length args) == 0 then error "please enter a destination to ping" else return ()
    
    let host = head args
        icmpData = BL.pack [1..32]                                       -- create 32 bytes of junk 
        pid = fromIntegral pidd
        packet = B.concat $ BL.toChunks $ buildPacket pid 1 icmpData     -- Create a packet
    address <- resolveAddressInfo host                                   -- get ip address of host to ping
    let (SockAddrInet _ hostname) = addrAddress address      
        pid = fromIntegral pidd
    ip <- inet_ntoa hostname                                             -- Get ip in string format "e.g 127.0.0.1"

    mySocket <- socket AF_INET Raw 1                                     -- Create a raw socket

    printPingInfo host ip
    ping mySocket (addrAddress address) packet

    close mySocket

-- Debug
{-printSocketInfo :: Socket -> IO ()
printSocketInfo sock = do
    putStrLn "***** Socket Information *****"

    putStr "Socket name: "
    a <- getSocketName sock
    putStrLn $ show a

    putStr "Socket port: "
    b <- socketPort sock
    putStrLn $ show b

    putStr "Connected: "
    c <- isConnected sock
    putStrLn $ show c

    putStr "Bound: "
    d <- isBound sock
    putStrLn $ show d

    putStr "Socket is listening: "
    e <- isListening sock
    putStrLn $ show e
-}
