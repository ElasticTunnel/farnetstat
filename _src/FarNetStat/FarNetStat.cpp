#include "stdafx.h"

#pragma pack(1)

#define MIN_BUFF 16
#define CHAR_BUFF 32
#define NCOUNT 3

enum {
	MTitle,
	MPro,
	MLocal,
	MRemote,
	MStatus
};

static struct PluginStartupInfo Info;

void WINAPI _export SetStartupInfo(const struct PluginStartupInfo *psi)
{
	Info = *psi;
}

char *GetMsg(int MsgId)
{
	return((char *)Info.GetMsg(Info.ModuleNumber, MsgId));
}

void WINAPI _export GetPluginInfo(struct PluginInfo *pi)
{
	static char *PluginMenuStrings[1];
	pi->StructSize = sizeof(struct PluginInfo);
	pi->Flags = 0;
	PluginMenuStrings[0] = GetMsg(MTitle);
	pi->PluginMenuStrings = PluginMenuStrings;
	pi->DiskMenuStrings = PluginMenuStrings;
	pi->DiskMenuStringsNumber = 1;
	pi->DiskMenuNumbers = 0;
	pi->PluginMenuStringsNumber = sizeof(PluginMenuStrings)/sizeof(PluginMenuStrings[0]);
}

HANDLE WINAPI _export OpenPlugin(int OpenFrom, int item)
{
	return &Info;
}

void WINAPI _export GetOpenPluginInfo(HANDLE hPlugin,
									  OpenPluginInfo *Info)
{ 
	static const char *CustomTitle = GetMsg(MTitle);
	static const char *CustomColumnTitles[4];
	CustomColumnTitles[0] = GetMsg(MPro);
	CustomColumnTitles[1] = GetMsg(MLocal);
	CustomColumnTitles[2] = GetMsg(MRemote);
	CustomColumnTitles[3] = GetMsg(MStatus);
	static PanelMode CustomPanelModes[10];
	static char ColumnTypes[] = "N, C0, C1, C2";
	static char ColumnWidths[] = "5, 21, 21, 20";
	for (int i = 0; i < 10; i++)
	{
		CustomPanelModes[i].ColumnTypes = ColumnTypes;
		CustomPanelModes[i].ColumnWidths = ColumnWidths;
		CustomPanelModes[i].ColumnTitles = (char **)&CustomColumnTitles;
		CustomPanelModes[i].FullScreen = FALSE;
		CustomPanelModes[i].DetailedStatus = TRUE;
		CustomPanelModes[i].AlignExtensions = TRUE;
		CustomPanelModes[i].CaseConversion = TRUE;
		CustomPanelModes[i].StatusColumnTypes = NULL;
		CustomPanelModes[i].StatusColumnWidths = NULL;
		CustomPanelModes[i].Reserved[0] = 0;
		CustomPanelModes[i].Reserved[1] = 0;
	}
	Info->StructSize = sizeof(OpenPluginInfo);
	Info->PanelModesArray = (const struct PanelMode *) &CustomPanelModes;
	Info->PanelModesNumber = 10;
    Info->PanelTitle = CustomTitle;
	Info->Flags = OPIF_ADDDOTS | OPIF_SHOWPRESERVECASE;
}


int WINAPI _export GetFindData(	HANDLE hPlugin,
								struct PluginPanelItem **pPanelItem,
								int *pItemsNumber,
								int OpMode)
{
#pragma pack(8)
	MIB_TCPTABLE *pTcpTable;
	pTcpTable = (MIB_TCPTABLE *) malloc(MIN_BUFF);
	DWORD dwSize = MIN_BUFF;
	BOOL Ok = FALSE;
	if (pTcpTable)
	{
		if (GetTcpTable(pTcpTable, &dwSize, TRUE) != NO_ERROR)
		{
			if (dwSize > MIN_BUFF)
			{
				free(pTcpTable);
				pTcpTable = (MIB_TCPTABLE *) malloc(dwSize);
				if ((pTcpTable) && (GetTcpTable(pTcpTable, &dwSize, TRUE) == NO_ERROR))
					Ok = TRUE;
			}
		}
		else
			Ok = TRUE;
	}

	MIB_UDPTABLE *pUdpTable;
	pUdpTable = (MIB_UDPTABLE *) malloc(MIN_BUFF);
	DWORD dwSizeUDP = MIN_BUFF;
	BOOL OkUDP = FALSE;

	if (pUdpTable)
	{
		if (GetUdpTable(pUdpTable, &dwSizeUDP, TRUE) != NO_ERROR)
		{
			if (dwSizeUDP > MIN_BUFF)
			{
				free(pUdpTable);
				pUdpTable = (MIB_UDPTABLE *) malloc(dwSizeUDP);
				if ((pUdpTable) && (GetUdpTable(pUdpTable, &dwSizeUDP, TRUE) == NO_ERROR))
					OkUDP = TRUE;
			}
		}
		else
			OkUDP = TRUE;
	}
	unsigned int Num = pTcpTable->dwNumEntries;
	unsigned int NumUDP = pUdpTable->dwNumEntries;
	WSAData wsadata;
	WSAStartup(MAKEWORD(2,2), &wsadata);

#pragma pack(1)
	PluginPanelItem *pItems = (PluginPanelItem *)malloc ((Num + NumUDP) * sizeof(PluginPanelItem));
	memset (pItems, 0, (Num + NumUDP) * sizeof PluginPanelItem); 

	if ((Ok) || (OkUDP))
	{
		unsigned int i = 0;
		if (Ok)
		for (; i < Num; i++)
		{
			char tmp_str[CHAR_BUFF];
			strcpy (pItems[i].FindData.cFileName, " tcp ");
			pItems[i].CustomColumnData = (char**) malloc (NCOUNT * sizeof(void *));
			pItems[i].CustomColumnNumber = NCOUNT;
			pItems[i].CustomColumnData[0] = (char *) malloc(CHAR_BUFF);
			memset(pItems[i].CustomColumnData[0], 0, CHAR_BUFF);
#pragma pack(8)
			DWORD dw_len = CHAR_BUFF;
			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = (WORD) pTcpTable->table[i].dwLocalPort;
			addr.sin_addr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
			memset(tmp_str, 0, CHAR_BUFF);
			WSAAddressToString((sockaddr *)&addr, sizeof(addr), NULL, (char *)&tmp_str, &dw_len);
#pragma pack(1)
			strcpy(pItems[i].CustomColumnData[0], tmp_str);
			pItems[i].CustomColumnData[1] = (char *) malloc(CHAR_BUFF);
			memset(pItems[i].CustomColumnData[1], 0, CHAR_BUFF);
#pragma pack(8)
			addr.sin_port = (WORD) pTcpTable->table[i].dwRemotePort;
			addr.sin_addr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
			memset(tmp_str, 0, CHAR_BUFF);
			WSAAddressToString((sockaddr *)&addr, sizeof(addr), NULL, (char *)&tmp_str, &dw_len);
#pragma pack(1)
			strcpy(pItems[i].CustomColumnData[1], tmp_str);
			pItems[i].CustomColumnData[2] = (char *) malloc(CHAR_BUFF);
			memset(pItems[i].CustomColumnData[2], 0, CHAR_BUFF);
#pragma pack(8)
			switch (pTcpTable->table[i].dwState)
#pragma pack(1)
			{
				case MIB_TCP_STATE_CLOSED:
					strcpy(pItems[i].CustomColumnData[2], "CLOSED");
					break;
				case MIB_TCP_STATE_LISTEN:
					strcpy(pItems[i].CustomColumnData[2], "LISTEN");
					break;
				case MIB_TCP_STATE_SYN_SENT:
					strcpy(pItems[i].CustomColumnData[2], "SYN_SENT");
					break;
				case MIB_TCP_STATE_SYN_RCVD:
					strcpy(pItems[i].CustomColumnData[2], "SYN_RCVD");
					break;
				case MIB_TCP_STATE_ESTAB:
					strcpy(pItems[i].CustomColumnData[2], "ESTAB");
					break;
				case MIB_TCP_STATE_FIN_WAIT1:
					strcpy(pItems[i].CustomColumnData[2], "FIN_WAIT1");
					break;
				case MIB_TCP_STATE_FIN_WAIT2:
					strcpy(pItems[i].CustomColumnData[2], "FIN_WAIT2");
					break;
				case MIB_TCP_STATE_CLOSE_WAIT:
					strcpy(pItems[i].CustomColumnData[2], "CLOSE_WAIT");
					break;
				case MIB_TCP_STATE_CLOSING:
					strcpy(pItems[i].CustomColumnData[2], "CLOSING");
					break;
				case MIB_TCP_STATE_LAST_ACK:
					strcpy(pItems[i].CustomColumnData[2], "LAST_ACK");
					break;
				case MIB_TCP_STATE_TIME_WAIT:
					strcpy(pItems[i].CustomColumnData[2], "TIME_WAIT");
					break;
				case MIB_TCP_STATE_DELETE_TCB:
					strcpy(pItems[i].CustomColumnData[2], "DELETE_TCB");
					break;
				default:
					strcpy(pItems[i].CustomColumnData[2], "UNKNOWN");
					break;
			}
		}
		if (OkUDP)
		for (; i < (Num + NumUDP); i++)
		{
			char tmp_str[CHAR_BUFF];
			strcpy (pItems[i].FindData.cFileName, " udp ");
			pItems[i].CustomColumnData = (char**) malloc (NCOUNT * sizeof(void *));
			pItems[i].CustomColumnNumber = NCOUNT;
			pItems[i].CustomColumnData[0] = (char *) malloc(CHAR_BUFF);
			memset(pItems[i].CustomColumnData[0], 0, CHAR_BUFF);
#pragma pack(8)
			DWORD dw_len = CHAR_BUFF;
			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = (WORD) pUdpTable->table[i - Num].dwLocalPort;
			addr.sin_addr.S_un.S_addr = pUdpTable->table[i - Num].dwLocalAddr;
			memset(tmp_str, 0, CHAR_BUFF);
			WSAAddressToString((sockaddr *)&addr, sizeof(addr), NULL, (char *)&tmp_str, &dw_len);
#pragma pack(1)
			strcpy(pItems[i].CustomColumnData[0], tmp_str);
			pItems[i].CustomColumnData[1] = (char *) malloc(CHAR_BUFF);
			memset(pItems[i].CustomColumnData[1], 0, CHAR_BUFF);
			strcpy(pItems[i].CustomColumnData[1], "*.*");
			pItems[i].CustomColumnData[2] = (char *) malloc(CHAR_BUFF);
			memset(pItems[i].CustomColumnData[2], 0, CHAR_BUFF);
		}
	}

	if (pTcpTable)
		free(pTcpTable);

	if (pUdpTable)
		free(pUdpTable);

    *pPanelItem = pItems; 
    *pItemsNumber = Num + NumUDP;
    return TRUE;
}

void WINAPI _export FreeFindData(HANDLE hPlugin,
								 struct PluginPanelItem *PanelItem,
								 int ItemsNumber)
{ 
	for (int i = 0; i < ItemsNumber; i++)
	{
		for (int j = 0; j < PanelItem[i].CustomColumnNumber; j++)
			free(PanelItem[i].CustomColumnData[j]);
		free(PanelItem[i].CustomColumnData);
	}
	free(PanelItem);
} 

int WINAPI _export ProcessEvent(HANDLE hPlugin,
								int Event,
								void *Param)
{
	if (Event == FE_IDLE)
	{
		//Info.Control(hPlugin, FCTL_GETPANELINFO, &PInfo);

		Info.Control(hPlugin, FCTL_UPDATEPANEL, (void *)TRUE);
		Info.Control(hPlugin, FCTL_REDRAWPANEL, NULL);
	}
	return FALSE;
}
