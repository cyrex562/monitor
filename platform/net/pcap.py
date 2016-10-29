import ctypes
import fnmatch
import inspect
import sys
from ctypes import *
from ctypes.util import find_library

# WIN32 = False
# HAVE_REMOTE = False

# if sys.platform.startswith('win'):
#     WIN32 = True
#     HAVE_REMOTE = True

# #define PCAP_VERSION_MAJOR 2
# Major libpcap dump file version.
PCAP_VERSION_MAJOR = 2
# #define PCAP_VERSION_MINOR 4
# Minor libpcap dump file version.
PCAP_VERSION_MINOR = 4
# #define PCAP_ERRBUF_SIZE 256
# Size to use when allocating the buffer that contains the libpcap errors.
PCAP_ERRBUF_SIZE = 256
# #define PCAP_IF_LOOPBACK 0x00000001
# interface is loopback
PCAP_IF_LOOPBACK = 1
# #define MODE_CAPT 0
# Capture mode, to be used when calling pcap_setmode().
MODE_CAPT = 0
# #define MODE_STAT 1
# 	Statistical mode, to be used when calling pcap_setmode().
MODE_STAT = 1

# u_short = c_ushort
# bpf_int32 = c_int
# u_int = c_uint
# c_uint = u_int
# pcap = c_void_p
# pcap_dumper = c_void_p
# u_char = c_ubyte
# FILE = c_void_p
# STRING = c_char_p
# typedef int 	bpf_int32 (already defined)
# 	32-bit integer
# typedef u_int 	c_uint (already defined)
# 	32-bit unsigned integer
# typedef struct pcap 	pcap_t
# 	Descriptor of an open capture instance. This structure is opaque to the
# user, that handles its content through the functions provided by wpcap.dll.
# pcap_t = pcap
# typedef struct pcap_dumper 	pcap_dumper_t
# 	libpcap savefile descriptor.
# pcap_dumper_t = pcap_dumper
# typedef struct pcap_if 	pcap_if_t
# 	Item in a list of interfaces, see pcap_if.
# pcap_if_t = PcapIf
# typedef struct pcap_addr 	pcap_addr_t
# 	Representation of an interface address, see pcap_addr.
# pcap_addr_t = PcapAddr
# values for enumeration 'pcap_direction_t'
# pcap_direction_t = c_int # enum

g_have_remote = False
if sys.platform == 'win32':
    c_socket = c_uint
    _lib = CDLL('wpcap.dll')
    g_have_remote = True
else:
    c_socket = c_int
    _lib = CDLL(find_library('pcap'))


class BpfInsn(Structure):
    """

    """
    _fields_ = [("code", c_ushort),
                ("jt", c_ubyte),
                ("jf", c_ubyte),
                ("k", c_uint)]


class BpfProgram(Structure):
    """

    """
    pass


BpfProgram._fields_ = [('bf_len', c_uint),
                       ('bf_insns', POINTER(BpfInsn))]


class BpfVersion(Structure):
    """

    """
    _fields_ = [("bv_major", c_ushort),
                ("bv_minor", c_ushort)]


class TimeVal(Structure):
    """

    """
    pass


TimeVal._fields_ = [('tv_sec', c_long),
                    ('tv_usec', c_long)]


class SockAddr(Structure):
    """
    sockaddr is used by pcap_addr.
    For exapmle if sa_family==socket.AF_INET then we need cast
    with sockaddr_in
    """
    _fields_ = [("sa_family", c_ushort),
                ("sa_data", c_char * 14)]


class PcapFileHeader(Structure):
    """
    struct  	pcap_file_header
    Header of a libpcap dump file.
    """
    _fields_ = [('magic', c_uint),
                ('version_major', c_ushort),
                ('version_minor', c_ushort),
                ('thiszone', c_int32),
                ('sigfigs', c_uint),
                ('snaplen', c_uint),
                ('linktype', c_uint)]


class PcapPktHdr(Structure):
    """
    struct  	pcap_pkthdr
    Header of a packet in the dump file.
    """
    _fields_ = [('ts', TimeVal),
                ('caplen', c_uint),
                ('len', c_uint)]


class PcapStat(Structure):
    """
    struct    pcap_stat
    Structure that keeps statistical values on an interface.
    """
    pass


_tmpList = [("ps_recv", c_uint), ("ps_drop", c_uint), ("ps_ifdrop", c_uint)]
if g_have_remote is True:
    _tmpList.append(("ps_capt", c_uint))
    _tmpList.append(("ps_sent", c_uint))
    _tmpList.append(("ps_netdrop", c_uint))
PcapStat._fields_ = _tmpList


class PcapAddr(Structure):
    """
    struct  	pcap_addr
    Representation of an interface address, used by pcap_findalldevs().
    """
    pass


PcapAddr._fields_ = [('next', POINTER(PcapAddr)),
                     ('addr', POINTER(SockAddr)),
                     ('netmask', POINTER(SockAddr)),
                     ('broadaddr', POINTER(SockAddr)),
                     ('dstaddr', POINTER(SockAddr))]


class PcapIf(Structure):
    """
    struct  	pcap_if
    Item in a list of interfaces, used by pcap_findalldevs().
    """
    pass


PcapIf._fields_ = [('next', POINTER(PcapIf)),
                   ('name', c_char_p),
                   ('description', c_char_p),
                   ('addresses', POINTER(PcapAddr)),
                   ('flags', c_uint)]

# typedef void(* pcap_handler )(u_char *user,
#               const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
# Prototype of the callback function that receives the packets.
pcap_handler = CFUNCTYPE(None, POINTER(c_ubyte), POINTER(PcapPktHdr),
                         POINTER(c_ubyte))

# pcap_t *   pcap_open_live (const char *device, int snaplen, int promisc,
#                            int to_ms, char *ebuf)
# 	Open a live capture from the network.
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = POINTER(c_void_p)
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]

# pcap_t *   pcap_open_dead (int linktype, int snaplen)
# 	Create a pcap_t structure without starting a capture.
pcap_open_dead = _lib.pcap_open_dead
pcap_open_dead.restype = POINTER(c_void_p)
pcap_open_dead.argtypes = [c_int, c_int]

# pcap_t *   pcap_open_offline (const char *fname, char *errbuf)
# 	Open a savefile in the tcpdump/libpcap format to read packets.
pcap_open_offline = _lib.pcap_open_offline
pcap_open_offline.restype = POINTER(c_void_p)
pcap_open_offline.argtypes = [c_char_p, c_char_p]

# pcap_dumper_t *   pcap_dump_open (pcap_t *p, const char *fname)
# 	Open a file to write packets.
pcap_dump_open = _lib.pcap_dump_open
pcap_dump_open.restype = POINTER(c_void_p)
pcap_dump_open.argtypes = [POINTER(c_void_p), c_char_p]

# int pcap_setnonblock (pcap_t *p, int nonblock, char *errbuf)
# 	Switch between blocking and nonblocking mode.
pcap_setnonblock = _lib.pcap_setnonblock
pcap_setnonblock.restype = c_int
pcap_setnonblock.argtypes = [POINTER(c_void_p), c_int, c_char_p]

# int pcap_getnonblock (pcap_t *p, char *errbuf)
# 	Get the "non-blocking" state of an interface.
pcap_getnonblock = _lib.pcap_getnonblock
pcap_getnonblock.restype = c_int
pcap_getnonblock.argtypes = [POINTER(c_void_p), c_char_p]

# int pcap_findalldevs (pcap_if_t **alldevsp, char *errbuf)
# 	Construct a list of network devices that can be opened with pcap_open_live().
pcap_findalldevs = _lib.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes = [POINTER(POINTER(PcapIf)), c_char_p]

# void pcap_freealldevs (pcap_if_t *alldevsp)
# 	Free an interface list returned by pcap_findalldevs().
pcap_freealldevs = _lib.pcap_freealldevs
pcap_freealldevs.restype = None
pcap_freealldevs.argtypes = [POINTER(PcapIf)]

# char *   pcap_lookupdev (char *errbuf)
# 	Return the first valid device in the system.
pcap_lookupdev = _lib.pcap_lookupdev
pcap_lookupdev.restype = c_char_p
pcap_lookupdev.argtypes = [c_char_p]

# int pcap_lookupnet (const char *device, c_uint *netp, c_uint *maskp,
#                     char *errbuf)
# Return the subnet and netmask of an interface.
pcap_lookupnet = _lib.pcap_lookupnet
pcap_lookupnet.restype = c_int
pcap_lookupnet.argtypes = [c_char_p, POINTER(c_uint), POINTER(c_uint),
                           c_char_p]

# int pcap_dispatch (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
# Collect a group of packets.
pcap_dispatch = _lib.pcap_dispatch
pcap_dispatch.restype = c_int
pcap_dispatch.argtypes = [POINTER(c_void_p), c_int, pcap_handler,
                          POINTER(c_ubyte)]

# int pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
# Collect a group of packets.
pcap_loop = _lib.pcap_loop
pcap_loop.restype = c_int
pcap_loop.argtypes = [POINTER(c_void_p), c_int, pcap_handler, POINTER(c_ubyte)]

# u_char * pcap_next (pcap_t *p, struct pcap_pkthdr *h)
# Return the next available packet.
pcap_next = _lib.pcap_next
pcap_next.restype = POINTER(c_ubyte)
pcap_next.argtypes = [POINTER(c_void_p), POINTER(PcapPktHdr)]

# int pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header,
#                   const u_char **pkt_data)
# Read a packet from an interface or from an offline capture.
pcap_next_ex = _lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [POINTER(c_void_p), POINTER(POINTER(PcapPktHdr)),
                         POINTER(POINTER(c_ubyte))]

# void pcap_breakloop (pcap_t *)
# set a flag that will force pcap_dispatch() or pcap_loop() to return rather
# than looping.
pcap_breakloop = _lib.pcap_breakloop
pcap_breakloop.restype = None
pcap_breakloop.argtypes = [POINTER(c_void_p)]

# int pcap_sendpacket (pcap_t *p, u_char *buf, int size)
# Send a raw packet.
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(c_void_p), POINTER(c_ubyte), c_int]

# void pcap_dump (u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
# Save a packet to disk.
pcap_dump = _lib.pcap_dump
pcap_dump.restype = None
pcap_dump.argtypes = [POINTER(c_void_p), POINTER(PcapPktHdr),
                      POINTER(c_ubyte)]

# long pcap_dump_ftell (pcap_dumper_t *)
# 	Return the file position for a "savefile".
pcap_dump_ftell = _lib.pcap_dump_ftell
pcap_dump_ftell.restype = c_long
pcap_dump_ftell.argtypes = [POINTER(c_void_p)]

# int pcap_compile (pcap_t *p, struct bpf_program *fp, char *str, int optimize,
#                   c_uint netmask)
# Compile a packet filter, converting an high level filtering expression (see
# Filtering expression syntax) in a program that can be interpreted by the
# kernel-level filtering engine.
pcap_compile = _lib.pcap_compile
pcap_compile.restype = c_int
pcap_compile.argtypes = [POINTER(c_void_p), POINTER(BpfProgram), c_char_p,
                         c_int,
                         c_uint]

# int pcap_compile_nopcap (int snaplen_arg, int linktype_arg,
#                          struct bpf_program *program, char *buf,
#                          int optimize, c_uint mask)
# Compile a packet filter without the need of opening an adapter. This function
# converts an high level filtering expression (see Filtering expression syntax)
# in a program that can be interpreted by the kernel-level filtering engine.
pcap_compile_nopcap = _lib.pcap_compile_nopcap
pcap_compile_nopcap.restype = c_int
pcap_compile_nopcap.argtypes = [c_int, c_int, POINTER(BpfProgram), c_char_p,
                                c_int, c_uint]

# int pcap_setfilter (pcap_t *p, struct bpf_program *fp)
# 	Associate a filter to a capture.
pcap_setfilter = _lib.pcap_setfilter
pcap_setfilter.restype = c_int
pcap_setfilter.argtypes = [POINTER(c_void_p), POINTER(BpfProgram)]

# void pcap_freecode (struct bpf_program *fp)
# 	Free a filter.
pcap_freecode = _lib.pcap_freecode
pcap_freecode.restype = None
pcap_freecode.argtypes = [POINTER(BpfProgram)]

# int pcap_datalink (pcap_t *p)
# 	Return the link layer of an adapter.
pcap_datalink = _lib.pcap_datalink
pcap_datalink.restype = c_int
pcap_datalink.argtypes = [POINTER(c_void_p)]

# int pcap_list_datalinks (pcap_t *p, int **dlt_buf)
# 	list datalinks
pcap_list_datalinks = _lib.pcap_list_datalinks
pcap_list_datalinks.restype = c_int
# pcap_list_datalinks.argtypes = [POINTER(pcap_t), POINTER(POINTER(c_int))]

# int pcap_set_datalink (pcap_t *p, int dlt)
# Set the current data link type of the pcap descriptor to the type specified
# by dlt. -1 is returned on failure.
pcap_set_datalink = _lib.pcap_set_datalink
pcap_set_datalink.restype = c_int
pcap_set_datalink.argtypes = [POINTER(c_void_p), c_int]

# int pcap_datalink_name_to_val (const char *name)
# Translates a data link type name, which is a DLT_ name with the DLT_ removed,
# to the corresponding data link type value. The translation is
# case-insensitive. -1 is returned on failure.
pcap_datalink_name_to_val = _lib.pcap_datalink_name_to_val
pcap_datalink_name_to_val.restype = c_int
pcap_datalink_name_to_val.argtypes = [c_char_p]

# const char * 	pcap_datalink_val_to_name (int dlt)
# Translates a data link type value to the corresponding data link type name.
# NULL is returned on failure.
pcap_datalink_val_to_name = _lib.pcap_datalink_val_to_name
pcap_datalink_val_to_name.restype = c_char_p
pcap_datalink_val_to_name.argtypes = [c_int]

# const char * 	pcap_datalink_val_to_description (int dlt)
# Translates a data link type value to a short description of that data link
# type. NULL is returned on failure.
pcap_datalink_val_to_description = _lib.pcap_datalink_val_to_description
pcap_datalink_val_to_description.restype = c_char_p
pcap_datalink_val_to_description.argtypes = [c_int]

# int pcap_snapshot (pcap_t *p)
# Return the dimension of the packet portion (in bytes) that is delivered to
# the application.
pcap_snapshot = _lib.pcap_snapshot
pcap_snapshot.restype = c_int
pcap_snapshot.argtypes = [POINTER(c_void_p)]

# int pcap_is_swapped (pcap_t *p)
# returns true if the current savefile uses a different byte order than the
# current system.
pcap_is_swapped = _lib.pcap_is_swapped
pcap_is_swapped.restype = c_int
pcap_is_swapped.argtypes = [POINTER(c_void_p)]

# int pcap_major_version (pcap_t *p)
# return the major version number of the pcap library used to write the
# savefile.
pcap_major_version = _lib.pcap_major_version
pcap_major_version.restype = c_int
pcap_major_version.argtypes = [POINTER(c_void_p)]

# int pcap_minor_version (pcap_t *p)
# return the minor version number of the pcap library used to write the
# savefile.
pcap_minor_version = _lib.pcap_minor_version
pcap_minor_version.restype = c_int
pcap_minor_version.argtypes = [POINTER(c_void_p)]

# FILE *   pcap_file (pcap_t *p)
# 	Return the standard stream of an offline capture.
pcap_file = _lib.pcap_file
pcap_file.restype = c_void_p
pcap_file.argtypes = [POINTER(c_void_p)]

# int pcap_stats (pcap_t *p, struct pcap_stat *ps)
# 	Return statistics on current capture.
pcap_stats = _lib.pcap_stats
pcap_stats.restype = c_int
pcap_stats.argtypes = [POINTER(c_void_p), POINTER(PcapStat)]

# void pcap_perror (pcap_t *p, char *prefix)
# 	print the text of the last pcap library error on stderr, prefixed by prefix.
pcap_perror = _lib.pcap_perror
pcap_perror.restype = None
pcap_perror.argtypes = [POINTER(c_void_p), c_char_p]

# char *   pcap_geterr (pcap_t *p)
# 	return the error text pertaining to the last pcap library error.
pcap_geterr = _lib.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [POINTER(c_void_p)]

# char *   pcap_strerror (int error)
# 	Provided in case strerror() isn't available.
pcap_strerror = _lib.pcap_strerror
pcap_strerror.restype = c_char_p
pcap_strerror.argtypes = [c_int]

# const char *   pcap_lib_version (void)
# Returns a pointer to a string giving information about the version of the
# libpcap library being used; note that it contains more information than just
# a version number.
pcap_lib_version = _lib.pcap_lib_version
pcap_lib_version.restype = c_char_p
pcap_lib_version.argtypes = []

# void pcap_close (pcap_t *p)
# 	close the files associated with p and deallocates resources.
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(c_void_p)]

# FILE *   pcap_dump_file (pcap_dumper_t *p)
# 	return the standard I/O stream of the 'savefile' opened by pcap_dump_open().
pcap_dump_file = _lib.pcap_dump_file
pcap_dump_file.restype = c_void_p
pcap_dump_file.argtypes = [POINTER(c_void_p)]

# int pcap_dump_flush (pcap_dumper_t *p)
# Flushes the output buffer to the ``savefile,'' so that any packets written
# with pcap_dump() but not yet written to the ``savefile'' will be written. -1
# is returned on error, 0 on success.
pcap_dump_flush = _lib.pcap_dump_flush
pcap_dump_flush.restype = c_int
pcap_dump_flush.argtypes = [POINTER(c_void_p)]

# void pcap_dump_close (pcap_dumper_t *p)
# 	Closes a savefile.
pcap_dump_close = _lib.pcap_dump_close
pcap_dump_close.restype = None
pcap_dump_close.argtypes = [POINTER(c_void_p)]

if sys.platform == 'win32':
    # HANDLE = c_void_p
    # Identifiers related to the new source syntax
    # define 	PCAP_SRC_FILE   2
    # define 	PCAP_SRC_IFLOCAL   3
    # define 	PCAP_SRC_IFREMOTE   4
    # Internal representation of the type of source in use (file, remote/local
    # interface).
    PCAP_SRC_FILE = 2
    PCAP_SRC_IFLOCAL = 3
    PCAP_SRC_IFREMOTE = 4
    # define 	PCAP_SRC_FILE_STRING   "file://"
    # define 	PCAP_SRC_IF_STRING   "rpcap://"
    # String that will be used to determine the type of source in use (file,
    # remote/local interface).
    PCAP_SRC_FILE_STRING = "file://"
    PCAP_SRC_IF_STRING = "rpcap://"
    # define 	PCAP_OPENFLAG_PROMISCUOUS   1
    # 	Defines if the adapter has to go in promiscuous mode.
    PCAP_OPENFLAG_PROMISCUOUS = 1
    # define 	PCAP_OPENFLAG_DATATX_UDP   2
    # 	Defines if the data trasfer (in case of a remote capture) has to be
    # done with UDP protocol.
    PCAP_OPENFLAG_DATATX_UDP = 2
    # define 	PCAP_OPENFLAG_NOCAPTURE_RPCAP   4
    PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4
    # 	Defines if the remote probe will capture its own generated traffic.
    # define 	PCAP_OPENFLAG_NOCAPTURE_LOCAL   8
    PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8
    # define 	PCAP_OPENFLAG_MAX_RESPONSIVENESS   16
    # 	This flag configures the adapter for maximum responsiveness.
    PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16
    # define 	PCAP_SAMP_NOSAMP   0
    # No sampling has to be done on the current capture.
    PCAP_SAMP_NOSAMP = 0
    # define 	PCAP_SAMP_1_EVERY_N   1
    # It defines that only 1 out of N packets must be returned to the user.
    PCAP_SAMP_1_EVERY_N = 1
    # define 	PCAP_SAMP_FIRST_AFTER_N_MS   2
    # It defines that we have to return 1 packet every N milliseconds.
    PCAP_SAMP_FIRST_AFTER_N_MS = 2
    # define 	RPCAP_RMTAUTH_NULL   0
    # It defines the NULL authentication.
    RPCAP_RMTAUTH_NULL = 0
    # define 	RPCAP_RMTAUTH_PWD   1
    # It defines the username/password authentication.
    RPCAP_RMTAUTH_PWD = 1
    # define 	PCAP_BUF_SIZE   1024
    # Defines the maximum buffer size in which address, port, interface names
    # are kept.
    PCAP_BUF_SIZE = 1024
    # define 	RPCAP_HOSTLIST_SIZE   1024
    # Maximum lenght of an host name (needed for the RPCAP active mode).
    RPCAP_HOSTLIST_SIZE = 1024


    class PcapSendQueue(Structure):
        """

        """

        _fields_ = [("maxlen", c_uint),
                    ("len", c_uint),
                    ("buffer", c_char_p)]


    class PcapRmtAuth(Structure):
        """
        struct  	pcap_rmtauth
        This structure keeps the information needed to autheticate the user on
        a remote machine
        """
        _fields_ = [("type", c_int),
                    ("username", c_char_p),
                    ("password", c_char_p)]


    class PcapSamp(Structure):
        """
        struct  	pcap_samp
        This structure defines the information related to sampling
        """
        _fields_ = [("method", c_int),
                    ("value", c_int)]

    # PAirpcapHandle 	pcap_get_airpcap_handle (pcap_t *p)
    # Returns the AirPcap handler associated with an adapter. This handler
    # can be used to change the wireless-related settings of the CACE
    # Technologies AirPcap wireless capture adapters.
    # bool pcap_offline_filter (struct bpf_program *prog,
    #                           const struct pcap_pkthdr *header,
    #                           const u_char *pkt_data)
    # Returns if a given filter applies to an offline packet.
    pcap_offline_filter = _lib.pcap_offline_filter
    pcap_offline_filter.restype = c_bool
    pcap_offline_filter.argtypes = [POINTER(BpfProgram), POINTER(PcapPktHdr),
                                    POINTER(c_ubyte)]

    # int pcap_live_dump (pcap_t *p, char *filename, int maxsize, int maxpacks)
    # 	Save a capture to file.
    pcap_live_dump = _lib.pcap_live_dump
    pcap_live_dump.restype = c_int
    pcap_live_dump.argtypes = [POINTER(c_void_p), POINTER(c_char), c_int, c_int]

    # int pcap_live_dump_ended (pcap_t *p, int sync)
    # Return the status of the kernel dump process, i.e. tells if one of the
    # limits defined with pcap_live_dump() has been reached.
    pcap_live_dump_ended = _lib.pcap_live_dump_ended
    pcap_live_dump_ended.restype = c_int
    pcap_live_dump_ended.argtypes = [POINTER(c_void_p), c_int]

    # struct pcap_stat *  pcap_stats_ex (pcap_t *p, int *pcap_stat_size)
    # Return statistics on current capture.
    pcap_stats_ex = _lib.pcap_stats_ex
    pcap_stats_ex.restype = POINTER(PcapStat)
    pcap_stats_ex.argtypes = [POINTER(c_void_p), POINTER(c_int)]

    # int pcap_setbuff (pcap_t *p, int dim)
    # Set the size of the kernel buffer associated with an adapter.
    pcap_setbuff = _lib.pcap_setbuff
    pcap_setbuff.restype = c_int
    pcap_setbuff.argtypes = [POINTER(c_void_p), c_int]

    # int pcap_setmode (pcap_t *p, int mode)
    # 	Set the working mode of the interface p to mode.
    pcap_setmode = _lib.pcap_setmode
    pcap_setmode.restype = c_int
    pcap_setmode.argtypes = [POINTER(c_void_p), c_int]

    # int pcap_setmintocopy (pcap_t *p, int size)
    # 	Set the minumum amount of data received by the kernel in a single call.
    pcap_setmintocopy = _lib.pcap_setmintocopy
    pcap_setmintocopy.restype = c_int
    pcap_setmintocopy.argtype = [POINTER(c_void_p), c_int]

    # HANDLE pcap_getevent (pcap_t *p)
    # 	Return the handle of the event associated with the interface p.
    pcap_getevent = _lib.pcap_getevent
    pcap_getevent.restype = c_void_p
    pcap_getevent.argtypes = [POINTER(c_void_p)]

    # pcap_send_queue * 	pcap_sendqueue_alloc (u_int memsize)
    # 	Allocate a send queue.
    pcap_sendqueue_alloc = _lib.pcap_sendqueue_alloc
    pcap_sendqueue_alloc.restype = POINTER(PcapSendQueue)
    pcap_sendqueue_alloc.argtypes = [c_uint]

    # void pcap_sendqueue_destroy (pcap_send_queue *queue)
    # 	Destroy a send queue.
    pcap_sendqueue_destroy = _lib.pcap_sendqueue_destroy
    pcap_sendqueue_destroy.restype = None
    pcap_sendqueue_destroy.argtypes = [POINTER(PcapSendQueue)]

    # int pcap_sendqueue_queue (pcap_send_queue *queue,
    #                           const struct pcap_pkthdr *pkt_header,
    #                           const u_char *pkt_data)
    # Add a packet to a send queue.
    pcap_sendqueue_queue = _lib.pcap_sendqueue_queue
    pcap_sendqueue_queue.restype = c_int
    pcap_sendqueue_queue.argtypes = [POINTER(PcapSendQueue),
                                     POINTER(PcapPktHdr), POINTER(c_ubyte)]

    # u_int pcap_sendqueue_transmit (pcap_t *p, pcap_send_queue *queue,
    #                               int sync)
    # Send a queue of raw packets to the network.
    pcap_sendqueue_transmit = _lib.pcap_sendqueue_transmit
    pcap_sendqueue_transmit.retype = c_uint
    pcap_sendqueue_transmit.argtypes = [POINTER(c_void_p),
                                        POINTER(PcapSendQueue), c_int]

    # int pcap_findalldevs_ex (char *source, struct pcap_rmtauth *auth,
    #                          pcap_if_t **alldevs, char *errbuf)
    # Create a list of network devices that can be opened with pcap_open().
    pcap_findalldevs_ex = _lib.pcap_findalldevs_ex
    pcap_findalldevs_ex.retype = c_int
    pcap_findalldevs_ex.argtypes = [c_char_p, POINTER(PcapRmtAuth),
                                    POINTER(POINTER(PcapIf)), c_char_p]

    # int pcap_createsrcstr (char *source, int type, const char *host,
    #                        const char *port, const char *name, char *errbuf)
    # Accept a set of strings (host name, port, ...), and it returns the
    # complete source string according to the new format
    # (e.g. 'rpcap://1.2.3.4/eth0').
    pcap_createsrcstr = _lib.pcap_createsrcstr
    pcap_createsrcstr.restype = c_int
    pcap_createsrcstr.argtypes = [c_char_p, c_int, c_char_p, c_char_p, c_char_p,
                                  c_char_p]

    # int pcap_parsesrcstr (const char *source, int *type, char *host,
    # char *port, char *name, char *errbuf)
    # Parse the source string and returns the pieces in which the source can be
    #   split.
    pcap_parsesrcstr = _lib.pcap_parsesrcstr
    pcap_parsesrcstr.retype = c_int
    pcap_parsesrcstr.argtypes = [c_char_p, POINTER(c_int), c_char_p, c_char_p,
                                 c_char_p,
                                 c_char_p]

    # pcap_t * 	pcap_open (const char *source, int snaplen, int flags,
    #                      int read_timeout, struct pcap_rmtauth *auth,
    #                      char *errbuf)
    # 	Open a generic source in order to capture / send (WinPcap only) traffic.
    pcap_open = _lib.pcap_open
    pcap_open.restype = POINTER(c_void_p)
    pcap_open.argtypes = [c_char_p, c_int, c_int, c_int, POINTER(PcapRmtAuth),
                          c_char_p]

    # struct pcap_samp *  pcap_setsampling (pcap_t *p)
    # 	Define a sampling method for packet capture.
    pcap_setsampling = _lib.pcap_setsampling
    pcap_setsampling.restype = POINTER(PcapSamp)
    pcap_setsampling.argtypes = [POINTER(c_void_p)]

    # SOCKET pcap_remoteact_accept (const char *address, const char *port,
    # const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth,
    # char *errbuf)
    # 	Block until a network connection is accepted (active mode only).
    pcap_remoteact_accept = _lib.pcap_remoteact_accept
    pcap_remoteact_accept.restype = c_socket
    pcap_remoteact_accept.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p,
                                      POINTER(PcapRmtAuth), c_char_p]

    # int pcap_remoteact_close (const char *host, char *errbuf)
    # 	Drop an active connection (active mode only).
    pcap_remoteact_close = _lib.pcap_remoteact_close
    pcap_remoteact_close.restypes = c_int
    pcap_remoteact_close.argtypes = [c_char_p, c_char_p]

    # void pcap_remoteact_cleanup ()
    # 	Clean the socket that is currently used in waiting active connections.
    pcap_remoteact_cleanup = _lib.pcap_remoteact_cleanup
    pcap_remoteact_cleanup.restypes = None
    pcap_remoteact_cleanup.argtypes = []

    # int pcap_remoteact_list (char *hostlist, char sep, int size, char *errbuf)
    # 	Return the hostname of the host that have an active connection with us
    # (active mode only).
    pcap_remoteact_list = _lib.pcap_remoteact_list
    pcap_remoteact_list.restype = c_int
    pcap_remoteact_list.argtypes = [c_char_p, c_char, c_int, c_char_p]



# class WinPcapDevices(object):
#     """
#
#     """
#
#     class PcapFindDevicesException(Exception):
#         """
#
#         """
#         pass
#
#     def __init__(self):
#         self._all_devices = None
#
#     def __enter__(self):
#         assert self._all_devices is None
#         all_devices = ctypes.POINTER(PcapIf)()
#         err_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
#         if pcap_findalldevs(ctypes.byref(all_devices), err_buffer) == -1:
#             raise self.PcapFindDevicesException(
#                 "Error in WinPcapDevices: %s\n" % err_buffer.value)
#         self._all_devices = all_devices
#         return self
#
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         if self._all_devices is not None:
#             pcap_freealldevs(self._all_devices)
#
#     def pcap_interface_iterator(self):
#         if self._all_devices is None:
#             raise self.PcapFindDevicesException(
#                 "WinPcapDevices guard not called, use 'with statement'")
#         pcap_interface = self._all_devices
#         while bool(pcap_interface):
#             yield pcap_interface.contents
#             pcap_interface = pcap_interface.contents.next
#
#     def __iter__(self):
#         return self.pcap_interface_iterator()
#
#     @classmethod
#     def list_devices(cls):
#         res = {}
#         with cls() as devices:
#             for device in devices:
#                 res[device.name.decode('utf-8')] = device.description.decode(
#                     'utf-8')
#         return res
#
#     @classmethod
#     def get_matching_device(cls, glob=None):
#         for name, description in cls.list_devices().items():
#             if fnmatch.fnmatch(description, glob):
#                 return name, description
#         return None, None


# class WinPcap(object):
#     """
#
#     """
#     # /* prototype of the packet handler */
#     # void packet_handler(u_char *param, const struct pcap_pkthdr *header,
#     #                     const u_char *pkt_data);
#     HANDLER_SIGNATURE = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte),
#                                          ctypes.POINTER(PcapPktHdr),
#                                          ctypes.POINTER(ctypes.c_ubyte))
#
#     def __init__(self, device_name, snap_length=65536, promiscuous=1,
#                  timeout=1000):
#         """
#         @param device_name the name of the device to open on context enter
#         @param snap_length specifies the snapshot length to be set on the
#             handle.
#         @param promiscuous  specifies if the interface is to be put into
#             promiscuous mode(0 or 1).
#         @param timeout specifies the read timeout in milliseconds.
#         """
#         self._handle = None
#         self._name = device_name.encode('utf-8')
#         self._snap_length = snap_length
#         self._promiscuous = promiscuous
#         self._timeout = timeout
#         self._err_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
#         self._callback = None
#         self._callback_wrapper = self.HANDLER_SIGNATURE(self.packet_handler)
#
#     def __enter__(self):
#         assert self._handle is None
#         self._handle = pcap_open_live(self._name, self._snap_length,
#                                       self._promiscuous, self._timeout,
#                                       self._err_buffer)
#         return self
#
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         if self._handle is not None:
#             pcap_close(self._handle)
#
#     def packet_handler(self, param, header, pkt_pointer):
#         assert inspect.isfunction(self._callback) or inspect.ismethod(
#             self._callback)
#         pkt_data = ctypes.string_at(pkt_pointer, header.contents.len)
#         return self._callback(self, param, header, pkt_data)
#
#     def stop(self):
#         pcap_breakloop(self._handle)
#
#     def run(self, callback=None, limit=0):
#         """
#         Start pcap's loop over the interface, calling the given callback for
#             each packet
#         @param callback a function receiving
#         @param limit TODO
#         """
#         assert self._handle is not None
#         # Set new callback
#         self._callback = callback
#         # Run loop with callback wrapper
#         pcap_loop(self._handle, limit, self._callback_wrapper, None)


# class WinPcapUtils(object):
#     """
#     Utilities and usage examples
#     """
#
#     @staticmethod
#     def packet_printer_callback(win_pcap, param, header, pkt_data):
#         try:
#             local_tv_sec = header.contents.ts.tv_sec
#             ltime = time.localtime(local_tv_sec)
#             timestr = time.strftime("%H:%M:%S", ltime)
#             print(("%s,%.6d len:%d" % (
#                 timestr, header.contents.ts.tv_usec, header.contents.len)))
#         except KeyboardInterrupt:
#             win_pcap.stop()
#             sys.exit(0)
#
#     @staticmethod
#     def capture_on(pattern, callback):
#         device_name, desc = WinPcapDevices.get_matching_device(pattern)
#         if device_name is not None:
#             with WinPcap(device_name) as capture:
#                 capture.run(callback=callback)
#
#     @classmethod
#     def capture_on_and_print(cls, pattern):
#         """
#         Usage example capture_on_and_print("*Intel*Ethernet") will capture
#           and print packets from an Intel Ethernet device
#         """
#         cls.capture_on(pattern, cls.packet_printer_callback)



class PcapError(Exception):
    pass
        

def get_pcap_dev_name(interface_name):
    """
    get the pcap device name that can be passed to pcap_open_live for a given interface name such as "eth0"
    Throws PcapError when the call to pcap_findalldevs fails.
    return: the pcap device name on success, or a blank string when not found.
    
    """
    all_devices = ctypes.POINTER(PcapIf)()
    err_buf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    result = pcap_findalldevs(ctypes.byref(all_devices), err_buf)
    pcap_dev_name = ""
    if result == 0: # success
        for dev in all_devices:
            if dev.description.find(interface_name) != -1:
                pcap_dev_name = dev.name
                break
    elif result == -1: # failure
        raise PcapError("failed to get list of pcap-capable devices, {}".format(err_buf.value))
    pcap_freealldevs(all_devices)
    return pcap_dev_name.encode('utf-8')


def open_pcap(interface_name, snap_len=0xffff, promisc=1, timeout=1000):
    dev_name = ""
    err_buf = ctypes.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    try:
        dev_name = pcap.get_pcap_dev_name(interface_name)
    except pcap.PcapError as pe:
        sys.stdout("error occurred getting pcap dev name for interface name, {}".format(pe))
        sys.exit(-1)
    if dev_name == "":
        sys.stderr("device name not found for interface name \"{}\"".format(interface_name))
        sys.exit(-1)
        
    h_pcap = pcap.pcap_open_live(dev_name, snap_len, promisc, timeout, err_buf)
    #if h_pcap == None:
    #    sys.stderr("error occurred opening device for packet capture, {}".format(err_buf.value))
    #    sys.exit(-1)
    if h_pcap == None:
        raise PcapError("failed to open device for capturing, {}".format(err_buf.value))

    return h_pcap


def get_next_pkt(h_pcap):
    pcap_hdr = POINTER(PcapPktHdr)()
    pcap_data = POINTER(c_ubyte)()
    err_buf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    pkt_ts = -1
    pkt_str = ""
    pkt_len = -1
    if result == 1:
        pkt_len = pcap_hdr.contents.len
        raw_ts = pcap_hdr.ts
        secs = int(raw_ts.tv_sec.value)
        usecs = int(raw_ts.tv_usec.value)
        pkt_ts = usecs + secs * 1000000
        result = pcap_next_ex(h_pcap, pcap_hdr, pcap_data)
    elif result == 0:
        sys.stdout("timeout occurred")
    elif result == -1:
        raise PcapError("failed to get packet, {}".format(err_buf))
    elif result == -2:
        sys.stdout("EOF")
    return pkt_ts, pkt_len, pkt_str
# END OF FILE #
