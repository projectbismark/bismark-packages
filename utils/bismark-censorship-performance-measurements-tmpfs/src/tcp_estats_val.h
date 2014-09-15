#ifndef _TCP_ESTATS_VAL_H_
#define _TCP_ESTATS_VAL_H_

#ifdef __KERNEL__
#include <net/sock.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/tcp_estats.h>
#else
#include <linux/types.h>
#include <inttypes.h>
#endif

union estats_val {
        __u64 o;
        __u32 t;
        __s32 s;
        __u16 w;
        __u8  b;
};

enum MIB_TABLE {
        PERF_TABLE,
        PATH_TABLE,
        STACK_TABLE,
        APP_TABLE,
        TUNE_TABLE,
        __MAX_TABLE
};
#define MAX_TABLE __MAX_TABLE

extern int max_index[];

extern union estats_val   perf_val_array[];
extern union estats_val   path_val_array[];
extern union estats_val  stack_val_array[];
extern union estats_val    app_val_array[];
extern union estats_val   tune_val_array[];

extern union estats_val *estats_val_array[MAX_TABLE];


#ifdef __KERNEL__
typedef union estats_val (*estats_rw_func_t)(struct tcp_estats*);

extern estats_rw_func_t   perf_func_array[];
extern estats_rw_func_t   path_func_array[];
extern estats_rw_func_t  stack_func_array[];
extern estats_rw_func_t    app_func_array[];
extern estats_rw_func_t   tune_func_array[];

extern estats_rw_func_t *estats_func_array[MAX_TABLE];
#endif

/*
enum tcp_estats_states {
	TCP_ESTATS_STATE_CLOSED = 1,
	TCP_ESTATS_STATE_LISTEN,
	TCP_ESTATS_STATE_SYNSENT,
	TCP_ESTATS_STATE_SYNRECEIVED,
	TCP_ESTATS_STATE_ESTABLISHED,
	TCP_ESTATS_STATE_FINWAIT1,
	TCP_ESTATS_STATE_FINWAIT2,
	TCP_ESTATS_STATE_CLOSEWAIT,
	TCP_ESTATS_STATE_LASTACK,
	TCP_ESTATS_STATE_CLOSING,
	TCP_ESTATS_STATE_TIMEWAIT,
	TCP_ESTATS_STATE_DELETECB
};
*/

struct estats_connection_spec {
    char rem_addr[17];
    char local_addr[17];
    uint16_t rem_port;
    uint16_t local_port;
};

enum TCP_ESTATS_TYPE {
        TCP_ESTATS_UNSIGNED64,
        TCP_ESTATS_UNSIGNED32,
        TCP_ESTATS_SIGNED32,
        TCP_ESTATS_UNSIGNED16,
        TCP_ESTATS_UNSIGNED8,
};

struct estats_var {
        union estats_val val;
        char *name;
//        int len;
        enum TCP_ESTATS_TYPE type;
};

extern struct estats_var   perf_var_array[];
extern struct estats_var   path_var_array[];
extern struct estats_var  stack_var_array[];
extern struct estats_var    app_var_array[];
extern struct estats_var   tune_var_array[];

extern struct estats_var *estats_var_array[MAX_TABLE];


typedef enum ESTATS_PERF_INDEX {
	SEGSOUT                 = 0,
	DATASEGSOUT,
	DATAOCTETSOUT,
	HCDATAOCTETSOUT, 
	SEGSRETRANS,
	OCTETSRETRANS,
	SEGSIN,
	DATASEGSIN,
	DATAOCTETSIN,
	HCDATAOCTETSIN, 
	ELAPSEDSECS,
	ELAPSEDMICROSECS,
	STARTTIMESTAMP,
	CURMSS,
	PIPESIZE,
	MAXPIPESIZE,
	SMOOTHEDRTT,
	CURRTO,
	CONGSIGNALS,
	CURCWND,
	CURSSTHRESH,
	TIMEOUTS,
	CURRWINSENT,
	MAXRWINSENT,
	ZERORWINSENT,
	CURRWINRCVD,
	MAXRWINRCVD,
	ZERORWINRCVD,
	SNDLIMTRANSRWIN,
	SNDLIMTRANSCWND,
	SNDLIMTRANSSND,
	SNDLIMTIMERWIN,
	SNDLIMTIMECWND,
	SNDLIMTIMESND,
        __PERF_INDEX_MAX
} ESTATS_PERF_INDEX;
#define PERF_INDEX_MAX __PERF_INDEX_MAX

typedef enum ESTATS_PATH_INDEX {
        RETRANTHRESH,
        NONRECOVDAEPISODES,
        SUMOCTETSREORDERED,
        NONRECOVDA,
        SAMPLERTT,
        RTTVAR,
        MAXRTT,
        MINRTT,
        SUMRTT,
        HCSUMRTT,
        COUNTRTT,
        MAXRTO,
        MINRTO,
        IPTTL,
        IPTOSIN,
        IPTOSOUT,
        PRECONGSUMCWND,
        PRECONGSUMRTT,
        POSTCONGSUMRTT,
        POSTCONGCOUNTRTT,
        ECNSIGNALS,
        DUPACKEPISODES,
        RCVRTT,
        DUPACKSOUT,
        CERCVD,
        ECESENT,
        __PATH_INDEX_MAX
} ESTATS_PATH_INDEX;
#define PATH_INDEX_MAX __PATH_INDEX_MAX

typedef enum ESTATS_STACK_INDEX {
	ACTIVEOPEN,
	MSSSENT,
	MSSRCVD,
	WINSCALESENT,
	WINSCALERCVD,
	TIMESTAMPS,
	ECN,
	WILLSENDSACK,
	WILLUSESACK,
	STATE,
	NAGLE,
	MAXSSCWND,
	MAXCACWND,
	MAXSSTHRESH,
	MINSSTHRESH,
	INRECOVERY,
	DUPACKSIN,
	SPURIOUSFRDETECTED,
	SPURIOUSRTODETECTED,
	SOFTERRORS,
	SOFTERRORREASON,
	SLOWSTART,
	CONGAVOID,
	OTHERREDUCTIONS,
	CONGOVERCOUNT,
	FASTRETRAN,
	SUBSEQUENTTIMEOUTS,
	CURTIMEOUTCOUNT,
	ABRUPTTIMEOUTS,
	SACKSRCVD,
	SACKBLOCKSRCVD,
	SENDSTALL,
	DSACKDUPS,
	MAXMSS,
	MINMSS,
	SNDINITIAL,
	RECINITIAL,
	CURRETXQUEUE,
	MAXRETXQUEUE,
	CURREASMQUEUE,
	MAXREASMQUEUE,
        __STACK_INDEX_MAX
} ESTATS_STACK_INDEX;
#define STACK_INDEX_MAX __STACK_INDEX_MAX

typedef enum ESTATS_APP_INDEX {
        SNDUNA,
        SNDNXT,
        SNDMAX,
        THRUOCTETSACKED,
        HCTHRUOCTETSACKED, 
        RCVNXT,
        THRUOCTETSRECEIVED,
        HCTHRUOCTETSRECEIVED, 
        CURAPPWQUEUE,
        MAXAPPWQUEUE,
        CURAPPRQUEUE,
        MAXAPPRQUEUE,
        __APP_INDEX_MAX
} ESTATS_APP_INDEX;
#define APP_INDEX_MAX __APP_INDEX_MAX

typedef enum ESTATS_TUNE_INDEX { 
        LIMCWND,
        LIMSSTHRESH,
        LIMRWIN,
        LIMMSS,
        __TUNE_INDEX_MAX
} ESTATS_TUNE_INDEX;
#define TUNE_INDEX_MAX __TUNE_INDEX_MAX

#ifdef __KERNEL__
void read_spec(struct estats_connection_spec *, struct tcp_estats *);
void read_LocalPort(void *buf, struct tcp_estats *stats);
void read_LocalAddress(void *buf, struct tcp_estats *stats);
void read_RemPort(void *buf, struct tcp_estats *stats);
void read_RemAddress(void *buf, struct tcp_estats *stats);

union estats_val read_SegsOut(struct tcp_estats *);
union estats_val read_DataSegsOut(struct tcp_estats *);
union estats_val read_DataOctetsOut(struct tcp_estats *);
union estats_val read_HCDataOctetsOut(struct tcp_estats *);
union estats_val read_SegsRetrans(struct tcp_estats *);
union estats_val read_OctetsRetrans(struct tcp_estats *);
union estats_val read_SegsIn(struct tcp_estats *);
union estats_val read_DataSegsIn(struct tcp_estats *);
union estats_val read_DataOctetsIn(struct tcp_estats *);
union estats_val read_HCDataOctetsIn(struct tcp_estats *);
union estats_val read_ElapsedSecs(struct tcp_estats *);
union estats_val read_ElapsedMicroSecs(struct tcp_estats *);
union estats_val read_StartTimeStamp(struct tcp_estats *);
union estats_val read_CurMSS(struct tcp_estats *);
union estats_val read_PipeSize(struct tcp_estats *);
union estats_val read_MaxPipeSize(struct tcp_estats *);
union estats_val read_SmoothedRTT(struct tcp_estats *);
union estats_val read_CurRTO(struct tcp_estats *);
union estats_val read_CongSignals(struct tcp_estats *);
union estats_val read_CurCwnd(struct tcp_estats *);
union estats_val read_CurSsthresh(struct tcp_estats *);
union estats_val read_Timeouts(struct tcp_estats *);
union estats_val read_CurRwinSent(struct tcp_estats *);
union estats_val read_MaxRwinSent(struct tcp_estats *);
union estats_val read_ZeroRwinSent(struct tcp_estats *);
union estats_val read_CurRwinRcvd(struct tcp_estats *);
union estats_val read_MaxRwinRcvd(struct tcp_estats *);
union estats_val read_ZeroRwinRcvd(struct tcp_estats *);
union estats_val read_SndLimTransRwin(struct tcp_estats *);
union estats_val read_SndLimTransCwnd(struct tcp_estats *);
union estats_val read_SndLimTransSnd(struct tcp_estats *);
union estats_val read_SndLimTimeRwin(struct tcp_estats *);
union estats_val read_SndLimTimeCwnd(struct tcp_estats *);
union estats_val read_SndLimTimeSnd(struct tcp_estats *);

union estats_val read_ActiveOpen(struct tcp_estats *);
union estats_val read_MSSSent(struct tcp_estats *);
union estats_val read_MSSRcvd(struct tcp_estats *);
union estats_val read_WinScaleSent(struct tcp_estats *);
union estats_val read_WinScaleRcvd(struct tcp_estats *);
union estats_val read_TimeStamps(struct tcp_estats *);
union estats_val read_ECN(struct tcp_estats *);
union estats_val read_WillSendSACK(struct tcp_estats *);
union estats_val read_WillUseSACK(struct tcp_estats *);
union estats_val read_State(struct tcp_estats *);
union estats_val read_Nagle(struct tcp_estats *);
union estats_val read_MaxSsCwnd(struct tcp_estats *);
union estats_val read_MaxCaCwnd(struct tcp_estats *);
union estats_val read_MaxSsthresh(struct tcp_estats *);
union estats_val read_MinSsthresh(struct tcp_estats *);
union estats_val read_InRecovery(struct tcp_estats *);
union estats_val read_DupAcksIn(struct tcp_estats *);
union estats_val read_SpuriousFrDetected(struct tcp_estats *);
union estats_val read_SpuriousRtoDetected(struct tcp_estats *);
union estats_val read_SoftErrors(struct tcp_estats *);
union estats_val read_SoftErrorReason(struct tcp_estats *);
union estats_val read_SlowStart(struct tcp_estats *);
union estats_val read_CongAvoid(struct tcp_estats *);
union estats_val read_OtherReductions(struct tcp_estats *);
union estats_val read_CongOverCount(struct tcp_estats *);
union estats_val read_FastRetran(struct tcp_estats *);
union estats_val read_SubsequentTimeouts(struct tcp_estats *);
union estats_val read_CurTimeoutCount(struct tcp_estats *);
union estats_val read_AbruptTimeouts(struct tcp_estats *);
union estats_val read_SACKsRcvd(struct tcp_estats *);
union estats_val read_SACKBlocksRcvd(struct tcp_estats *);
union estats_val read_SendStall(struct tcp_estats *);
union estats_val read_DSACKDups(struct tcp_estats *);
union estats_val read_MaxMSS(struct tcp_estats *);
union estats_val read_MinMSS(struct tcp_estats *);
union estats_val read_SndInitial(struct tcp_estats *);
union estats_val read_RecInitial(struct tcp_estats *);
union estats_val read_CurRetxQueue(struct tcp_estats *);
union estats_val read_MaxRetxQueue(struct tcp_estats *);
union estats_val read_CurReasmQueue(struct tcp_estats *);
union estats_val read_MaxReasmQueue(struct tcp_estats *);

union estats_val read_RetranThresh(struct tcp_estats *);
union estats_val read_NonRecovDAEpisodes(struct tcp_estats *);
union estats_val read_SumOctetsReordered(struct tcp_estats *);
union estats_val read_NonRecovDA(struct tcp_estats *);
union estats_val read_SampleRTT(struct tcp_estats *);
union estats_val read_RTTVar(struct tcp_estats *);
union estats_val read_MaxRTT(struct tcp_estats *);
union estats_val read_MinRTT(struct tcp_estats *);
union estats_val read_SumRTT(struct tcp_estats *);
union estats_val read_HCSumRTT(struct tcp_estats *);
union estats_val read_CountRTT(struct tcp_estats *);
union estats_val read_MaxRTO(struct tcp_estats *);
union estats_val read_MinRTO(struct tcp_estats *);
union estats_val read_IpTtl(struct tcp_estats *);
union estats_val read_IpTosIn(struct tcp_estats *);
union estats_val read_IpTosOut(struct tcp_estats *);
union estats_val read_PreCongSumCwnd(struct tcp_estats *);
union estats_val read_PreCongSumRTT(struct tcp_estats *);
union estats_val read_PostCongSumRTT(struct tcp_estats *);
union estats_val read_PostCongCountRTT(struct tcp_estats *);
union estats_val read_ECNsignals(struct tcp_estats *);
union estats_val read_DupAckEpisodes(struct tcp_estats *);
union estats_val read_RcvRTT(struct tcp_estats *);
union estats_val read_DupAcksOut(struct tcp_estats *);
union estats_val read_CERcvd(struct tcp_estats *);
union estats_val read_ECESent(struct tcp_estats *);

union estats_val read_SndUna(struct tcp_estats *);
union estats_val read_SndNxt(struct tcp_estats *);
union estats_val read_SndMax(struct tcp_estats *);
union estats_val read_ThruOctetsAcked(struct tcp_estats *);
union estats_val read_HCThruOctetsAcked(struct tcp_estats *);
union estats_val read_RcvNxt(struct tcp_estats *);
union estats_val read_ThruOctetsReceived(struct tcp_estats *);
union estats_val read_HCThruOctetsReceived(struct tcp_estats *);
union estats_val read_CurAppWQueue(struct tcp_estats *);
union estats_val read_MaxAppWQueue(struct tcp_estats *);
union estats_val read_CurAppRQueue(struct tcp_estats *);
union estats_val read_MaxAppRQueue(struct tcp_estats *);

union estats_val read_LimCwnd(struct tcp_estats *);
union estats_val read_LimSsthresh(struct tcp_estats *);
union estats_val read_LimRwin(struct tcp_estats *);
union estats_val read_LimMSS(struct tcp_estats *);
#endif

#endif /* _TCP_ESTATS_VAL_H_ */
