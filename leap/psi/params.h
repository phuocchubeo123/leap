// parameters to choose OT protocols
// IKNP OT extension, otherwise SilentOT (configure with -DLEAP_SILENT=ON for SilentOT)
#ifndef LEAP_SILENT
#define IKNP
#endif
// enables Kyber OT, otherwise SimplestOT (not PQ-secure) is used
#define KYBER_OT

