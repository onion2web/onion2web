package onion2web

const SNIWait = 30			// Waiting for initial packet bytes
const SNIWait2 = 15			// Waiting for rest of the hello packet
const ReadTimeout = 60		// Waiting for incoming bytes on a socket
const LongReadTimeout = 700	// Allow long pauses after initial read on during pipe
const WriteTimeout = 15		// For how long a single Write() can block
const SocksDialTimeout = 30

const Version = 1