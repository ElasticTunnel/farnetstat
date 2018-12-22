#include "stdafx.h"

#pragma pack(2)

#define MIN_BUFF 16
#define CHAR_BUFF 32
#define NCOUNT 3
#define PORTSLST "ports.lst"
#define BUFFLEN 1024
#define RESOLVE "Resolve"
#define AUTOREFRESH "AutoRefresh"

enum {
	MTitle,
	MPro,
	MLocal,
	MRemote,
	MStatus,
	MOK,
	MCancel,
	MResolve,
	MAutoRefresh
};

const int DIALOG_WIDTH = 45;
const int DIALOG_HEIGHT = 9;
static struct PluginStartupInfo Info;
static char *UDPports[65536];
static char *TCPports[65536];
static BOOL Resolve = FALSE;
static BOOL AutoRefresh = TRUE;
static BOOL PortsLoaded = FALSE;
static CRITICAL_SECTION cs;

struct IPNameSave
{
	DWORD IP;
	char *Name;
	IPNameSave *Next;
};

IPNameSave *IPNameSaveHead = NULL;

struct InitDialogItem
{
	int Type;
	int X1;
	int Y1;
	int X2;
	int Y2;
	int Focus;
	int Selected;
	unsigned int Flags;
	int DefaultButton;
	char *Data;
};

struct SingleInitDialogItem
{
	unsigned char Type;
	unsigned char X1,Y1,X2,Y2;
	signed char Data;
};

char *GetNameByIP(DWORD IP)
{
	char *ret = NULL;
	EnterCriticalSection(&cs);
	IPNameSave *IPNameTemp = IPNameSaveHead;
	while (IPNameTemp)
	{
		if (IPNameTemp->IP == IP)
		{
			ret = IPNameTemp->Name;
			break;
		}
		IPNameTemp = IPNameTemp->Next;
	}
	LeaveCriticalSection(&cs);
	return ret;
}

void SaveIP(DWORD IP, char *Name)
{
	if (GetNameByIP(IP) == NULL)
	{
		EnterCriticalSection(&cs);
		IPNameSave *IPNameTemp = (struct IPNameSave *)malloc(sizeof(IPNameSave));
		if (IPNameTemp)
		{
			memset(IPNameTemp, 0, sizeof(IPNameSave));
			IPNameTemp->Next = IPNameSaveHead;
			IPNameSaveHead = IPNameTemp;
			IPNameTemp->IP = IP;
			if (Name)
			{
				IPNameTemp->Name = (char *)malloc(strlen(Name) + 1);
				strcpy(IPNameTemp->Name, Name);
			}
		}
		LeaveCriticalSection(&cs);
	}
}

char *GetMsg(int MsgId)
{
	return((char *)Info.GetMsg(Info.ModuleNumber, MsgId));
}

void InitDialogItems(	const struct SingleInitDialogItem *Init,
						struct FarDialogItem *Item,
						int ItemsNumber)
{
	struct FarDialogItem *PItem = Item;
	const struct SingleInitDialogItem *PInit = Init;
	for (int i = 0;i < ItemsNumber; i++, PItem++, PInit++)
	{
		PItem->Type = PInit->Type;
		PItem->X1 = PInit->X1;
		PItem->Y1 = PInit->Y1;
		PItem->X2 = PInit->X2;
		PItem->Y2 = PInit->Y2;
		PItem->Focus = 0;
		PItem->Selected = 0;
		PItem->DefaultButton = 0;
		switch(PInit->X2)
		{
			case 255:
				PItem->Flags = DIF_CENTERGROUP;
			break;
			default:  
				PItem->Flags = 0;
			break;
		}
		lstrcpy(PItem->Data, PInit->Data != -1 ? GetMsg(PInit->Data) : "");
	}
}

void AddPortInfo(char *pStr)
{
	DWORD dwPort;
	char comment[1024], port[1024], proto[1024];
	memset(comment, 0, sizeof(comment));
	memset(port, 0, sizeof(port));
	memset(proto, 0, sizeof(proto));
	sscanf(pStr, "%s %[0-9] %s", &comment, &port, &proto);
	dwPort = atoi(port);
	if (dwPort < 65536)
	{
		char *buff = NULL;
		buff = (char *)malloc(strlen(comment) + 1);
		if (buff)
			strcpy(buff, comment);
		if (proto[1] == 't')
		{
			if (TCPports[dwPort])
				free(TCPports[dwPort]);
			TCPports[dwPort] = buff;
		}
		else
		{
			if (UDPports[dwPort])
				free(UDPports[dwPort]);
			UDPports[dwPort] = buff;
		}
	}
}

char *ModuleName()
{
	return(Info.ModuleName);
}

void LoadPorts()
{
	char *ModName = ModuleName();
	char *szFileName;
	szFileName = (char *)malloc(strlen(ModName) + 8);
	if (szFileName)
	{
		memset(szFileName, 0, strlen(ModName) + 8);
		strcpy(szFileName, ModName);
		char *pointer = szFileName + strlen(ModName) + 8;
		while ((strlen(szFileName) > 0) && (*pointer != '\\'))
		{
			*pointer = 0;
			pointer--;
		}
		strcat(szFileName, PORTSLST);
	}
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(	szFileName,
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL, 
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);
	if ((szFileName) && (hFile != INVALID_HANDLE_VALUE))
	{
		char Buffer[BUFFLEN];
		DWORD NumBytes, pBytes, index;
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
		index = 0;
		memset(Buffer, 0, BUFFLEN);
		do {
			NumBytes = 1;
			pBytes = 0;
			BOOL res = ReadFile(hFile, &Buffer[index], NumBytes, &pBytes, NULL);
			if ((res) && (pBytes == 1))
			{
				if (Buffer[index] == '\n')
				{
					AddPortInfo((char *)&Buffer);
					index = 0;
					memset(Buffer, 0, BUFFLEN);
					continue;
				}
			}
			else
			{
				if (index != 0)
					AddPortInfo((char *)&Buffer);
				break;
			}
			index++;
		} while (TRUE);
	}
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (szFileName)
		free(szFileName);
}

int WINAPI _export Configure(int ItemNumber)
{
	static const struct SingleInitDialogItem InitItems[] = {
		DI_DOUBLEBOX, 3, 1, DIALOG_WIDTH - 4, DIALOG_HEIGHT - 2, MTitle,
		DI_CHECKBOX, 5, 3, 0, 0, MResolve,
		DI_CHECKBOX, 5, 4, 0, 0, MAutoRefresh,
		DI_BUTTON, 0, 6, 255, 0, MOK,
		DI_BUTTON, 0, 6, 255, 0, MCancel
	};

	static struct FarDialogItem DialogItems[sizeof(InitItems)/sizeof(InitItems[0])];
	InitDialogItems(InitItems, DialogItems, sizeof(InitItems)/sizeof(InitItems[0]));

	DialogItems[1].Selected = Resolve;
	DialogItems[2].Selected = AutoRefresh;

	int ExitCode = Info.Dialog(	Info.ModuleNumber,
								-1, -1, DIALOG_WIDTH, DIALOG_HEIGHT,
								GetMsg(MTitle),
								DialogItems,
								sizeof(DialogItems) / sizeof(DialogItems[0]));
	if (ExitCode != 3)
		return FALSE;

	HKEY handle_reg_key;

	if (RegCreateKeyEx(	HKEY_CURRENT_USER,
						"Software\\bobik\\FarNetStat",
						NULL,
						NULL,
						REG_OPTION_NON_VOLATILE,
						KEY_ALL_ACCESS,
						NULL,
						&handle_reg_key,
						NULL) == ERROR_SUCCESS)
	{
		DWORD chk = DialogItems[1].Selected;
		RegSetValueEx(	handle_reg_key,
						RESOLVE,
						NULL,
						REG_DWORD,
						(LPBYTE)&chk,
						sizeof(DWORD));
		chk = DialogItems[2].Selected;
		RegSetValueEx(	handle_reg_key,
						AUTOREFRESH,
						NULL,
						REG_DWORD,
						(LPBYTE)&chk,
						sizeof(DWORD));
		RegCloseKey(handle_reg_key);
	}
	Resolve = DialogItems[1].Selected;
	AutoRefresh = DialogItems[2].Selected;
	if ((Resolve) && (!PortsLoaded))
	{
		LoadPorts();
		PortsLoaded = TRUE;
	}
	return TRUE;
}

void WINAPI _export SetStartupInfo(const struct PluginStartupInfo *psi)
{
	Info = *psi;

	InitializeCriticalSection(&cs);

	WSAData wsadata;
	WSAStartup(MAKEWORD(2,2), &wsadata);

	HKEY handle_reg_key;
	DWORD tmp_dat;
	if (RegOpenKeyEx(	HKEY_CURRENT_USER,
						"Software\\bobik\\FarNetStat",
						NULL,
						KEY_READ,
						&handle_reg_key) == ERROR_SUCCESS)
	{
		DWORD chk = Resolve;
		tmp_dat = sizeof(DWORD);
		RegQueryValueEx(	handle_reg_key,
							RESOLVE,
							NULL,
							NULL,
							(LPBYTE)&chk,
							&tmp_dat);
		Resolve = chk;
		tmp_dat = sizeof(DWORD);
		chk = AutoRefresh;
		RegQueryValueEx(	handle_reg_key,
							AUTOREFRESH,
							NULL,
							NULL,
							(LPBYTE)&chk,
							&tmp_dat);
		AutoRefresh = chk;
		RegCloseKey(handle_reg_key);
	}
	memset(UDPports, 0, sizeof(UDPports));
	memset(TCPports, 0, sizeof(TCPports));
	if (Resolve)
	{
		LoadPorts();
		PortsLoaded = TRUE;
	}
}

void WINAPI _export ExitFAR(void)
{
	for(int i = 0; i < 65536; i++)
	{
		if (UDPports[i])
			free(UDPports[i]);
		if (TCPports[i])
			free(TCPports[i]);
	}


	EnterCriticalSection(&cs);
	IPNameSave *IPNameTmp;
	IPNameSave *IPNameTemp = IPNameSaveHead;
	while (IPNameTemp)
	{
		if (IPNameTemp->Name)
			free(IPNameTemp->Name);
		IPNameTmp = IPNameTemp;
		IPNameTemp = IPNameTemp->Next;
		free(IPNameTmp);
	}
	LeaveCriticalSection(&cs);
	DeleteCriticalSection(&cs);
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
	pi->PluginConfigStrings = PluginMenuStrings;
	pi->PluginConfigStringsNumber = 1;
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
	static char ColumnWidths[] = "5, 0, 0, 11";
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

char *TranslateIP(DWORD IP)
{
	static char buff[32];
	memset(buff, 0, sizeof(buff));
	char tmp[32];
	memset(tmp, 0, sizeof(tmp));
	DWORD temp = IP & 255;
	itoa(temp, tmp, 10);
	strcat(buff, tmp);
	strcat(buff, ".");
	memset(tmp, 0, sizeof(tmp));
	temp = (IP >> 8) & 255;
	itoa(temp, tmp, 10);
	strcat(buff, tmp);
	strcat(buff, ".");
	memset(tmp, 0, sizeof(tmp));
	temp = (IP >> 16) & 255;
	itoa(temp, tmp, 10);
	strcat(buff, tmp);
	strcat(buff, ".");
	memset(tmp, 0, sizeof(tmp));
	temp = (IP >> 24)  & 255;
	itoa(temp, tmp, 10);
	strcat(buff, tmp);
	return (char *)&buff;
}

void ResolveThread(DWORD *IP)
{
	DWORD ip = *IP;
	free(IP);
	int LastError = 0;
	char *TableName = GetNameByIP(ip);
	struct hostent *host;
	if (!TableName)
	{
		host = gethostbyaddr((char *)&ip, sizeof(ip), AF_INET);
		LastError = WSAGetLastError();
		if (LastError != 0)
		{
			TableName = TranslateIP(ip);
			SaveIP(ip, TableName);
		}
		else
			SaveIP(ip, host->h_name);
	}
}

char *ResolveIP(DWORD IP)
{
	int LastError = 0;
	char *TableName = GetNameByIP(IP);
	if (!TableName)
	{
		TableName = TranslateIP(IP);
		DWORD *ip = (DWORD *)malloc(sizeof(DWORD));
		*ip = IP;
		DWORD dwDummy = NULL;
		HANDLE hTh = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ResolveThread, ip, NULL, &dwDummy);
		CloseHandle(hTh);
	}
	return TableName;
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

#pragma pack(2)
	PluginPanelItem *pItems = (PluginPanelItem *)malloc ((Num + NumUDP) * sizeof(PluginPanelItem));
	memset (pItems, 0, (Num + NumUDP) * sizeof PluginPanelItem); 

	if ((Ok) || (OkUDP))
	{
		unsigned int i = 0;
		if (Ok)
		for (; i < Num; i++)
		{
			strcpy (pItems[i].FindData.cFileName, " tcp ");
			pItems[i].CustomColumnData = (char**) malloc (NCOUNT * sizeof(void *));
			pItems[i].CustomColumnNumber = NCOUNT;
			if (Resolve == TRUE)
			{
#pragma pack(8)
				DWORD len = 2;
				DWORD ip = pTcpTable->table[i].dwLocalAddr;
				u_short nPort = htons((unsigned short)pTcpTable->table[i].dwLocalPort);
#pragma pack(2)
				char *TableName = ResolveIP(ip);
				char *pBuff;
				if (TableName)
					len += strlen(TableName);				
				if (TCPports[nPort])
					len += strlen(TCPports[nPort]);
				else
					len += 5;
				pBuff = (char *) malloc(len);
				if (pBuff)
				{
					if (TableName)
						strcpy(pBuff, TableName);
					else
						strcpy(pBuff, "");
					strcat(pBuff, ":");
					if (TCPports[nPort])
						strcat(pBuff, TCPports[nPort]);
					else
					{
						char buff[MIN_BUFF];
						itoa(nPort, buff, 10);
						strcat(pBuff, buff);
					}
				}
				pItems[i].CustomColumnData[0] = pBuff;

				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN)
				{
					char *tBuff = (char *)malloc(1);
					if (tBuff)
						memset(tBuff, 0, 1);
					pItems[i].CustomColumnData[1] = tBuff;
				}
				else
				{
#pragma pack(8)
					DWORD ip = pTcpTable->table[i].dwRemoteAddr;
					nPort = htons((unsigned short)pTcpTable->table[i].dwRemotePort);
#pragma pack(2)
					char *TableName = ResolveIP(ip);

					len = 2;
					if (TableName)
						len += strlen(TableName);
					if (TCPports[nPort])
						len += strlen(TCPports[nPort]);
					else
						len += 5;
					pBuff = (char *) malloc(len);
					if (pBuff)
					{
						if (TableName)
							strcpy(pBuff, TableName);
						strcat(pBuff, ":");
						if (TCPports[nPort])
							strcat(pBuff, TCPports[nPort]);
						else
						{
							char buff[MIN_BUFF];
							itoa(nPort, buff, 10);
							strcat(pBuff, buff);
						}
					}
					pItems[i].CustomColumnData[1] = pBuff;
				}
			}
			else
			{
				pItems[i].CustomColumnData[0] = (char *) malloc(CHAR_BUFF);
				memset(pItems[i].CustomColumnData[0], 0, CHAR_BUFF);
#pragma pack(8)
				DWORD ip = pTcpTable->table[i].dwLocalAddr;
				u_short nPort = htons((unsigned short)pTcpTable->table[i].dwLocalPort);
#pragma pack(2)
				char *TransBuff = TranslateIP(ip);
				if (TransBuff)
					strcpy(pItems[i].CustomColumnData[0], TransBuff);
				strcat(pItems[i].CustomColumnData[0], ":");
				char buff[MIN_BUFF];
				memset(buff, 0, sizeof(buff));
				itoa(nPort, buff, 10);
				strcat(pItems[i].CustomColumnData[0], buff);
				
				pItems[i].CustomColumnData[1] = (char *) malloc(CHAR_BUFF);
				memset(pItems[i].CustomColumnData[1], 0, CHAR_BUFF);
				if (pTcpTable->table[i].dwState != MIB_TCP_STATE_LISTEN)
				{
#pragma pack(8)
					ip = pTcpTable->table[i].dwRemoteAddr;
					nPort = htons((unsigned short)pTcpTable->table[i].dwRemotePort);
#pragma pack(2)
					TransBuff = TranslateIP(ip);
					if (TransBuff)
						strcpy(pItems[i].CustomColumnData[1], TransBuff);
					strcat(pItems[i].CustomColumnData[1], ":");
					memset(buff, 0, sizeof(buff));
					itoa(nPort, buff, 10);
					strcat(pItems[i].CustomColumnData[1], buff);
				}
			}
			pItems[i].CustomColumnData[2] = (char *) malloc(CHAR_BUFF);
			memset(pItems[i].CustomColumnData[2], 0, CHAR_BUFF);
#pragma pack(8)
			switch (pTcpTable->table[i].dwState)
#pragma pack(2)
			{
				case MIB_TCP_STATE_CLOSED:
					strcpy(pItems[i].CustomColumnData[2], "CLOSED");
					break;
				case MIB_TCP_STATE_LISTEN:
					strcpy(pItems[i].CustomColumnData[2], "LISTENING");
					break;
				case MIB_TCP_STATE_SYN_SENT:
					strcpy(pItems[i].CustomColumnData[2], "SYN SENT");
					break;
				case MIB_TCP_STATE_SYN_RCVD:
					strcpy(pItems[i].CustomColumnData[2], "SYN RCVD");
					break;
				case MIB_TCP_STATE_ESTAB:
					strcpy(pItems[i].CustomColumnData[2], "ESTABLISHED");
					break;
				case MIB_TCP_STATE_FIN_WAIT1:
					strcpy(pItems[i].CustomColumnData[2], "FIN WAIT1");
					break;
				case MIB_TCP_STATE_FIN_WAIT2:
					strcpy(pItems[i].CustomColumnData[2], "FIN WAIT2");
					break;
				case MIB_TCP_STATE_CLOSE_WAIT:
					strcpy(pItems[i].CustomColumnData[2], "CLOSE WAIT");
					break;
				case MIB_TCP_STATE_CLOSING:
					strcpy(pItems[i].CustomColumnData[2], "CLOSING");
					break;
				case MIB_TCP_STATE_LAST_ACK:
					strcpy(pItems[i].CustomColumnData[2], "LAST ACK");
					break;
				case MIB_TCP_STATE_TIME_WAIT:
					strcpy(pItems[i].CustomColumnData[2], "TIME WAIT");
					break;
				case MIB_TCP_STATE_DELETE_TCB:
					strcpy(pItems[i].CustomColumnData[2], "DELETE");
					break;
				default:
					strcpy(pItems[i].CustomColumnData[2], "UNKNOWN");
					break;
			}
		}
		if (OkUDP)
		for (; i < (Num + NumUDP); i++)
		{
			strcpy (pItems[i].FindData.cFileName, " udp ");
			pItems[i].CustomColumnData = (char**) malloc (NCOUNT * sizeof(void *));
			pItems[i].CustomColumnNumber = NCOUNT;

			if (Resolve == TRUE)
			{
#pragma pack(8)
				DWORD ip = pUdpTable->table[i - Num].dwLocalAddr;
				u_short nPort = htons((unsigned short)pUdpTable->table[i - Num].dwLocalPort);
#pragma pack(2)
				char *TableName = ResolveIP(ip);
				char *pBuff;
				int len = 2;
				if (TableName)
					len += strlen(TableName);
				if (UDPports[nPort])
					len += strlen(UDPports[nPort]);
				else
					len += 5;
				pBuff = (char *) malloc(len);
				if (pBuff)
				{
					if (TableName)
						strcpy(pBuff, TableName);
					strcat(pBuff, ":");
					if (UDPports[nPort])
						strcat(pBuff, UDPports[nPort]);
					else
					{
						char buff[MIN_BUFF];
						itoa(nPort, buff, 10);
						strcat(pBuff, buff);
					}
				}
				pItems[i].CustomColumnData[0] = pBuff;
			}
			else
			{				
				pItems[i].CustomColumnData[0] = (char *) malloc(CHAR_BUFF);
				memset(pItems[i].CustomColumnData[0], 0, CHAR_BUFF);
#pragma pack(8)
				DWORD ip = pUdpTable->table[i - Num].dwLocalAddr;
				u_short nPort = htons((unsigned short)pUdpTable->table[i - Num].dwLocalPort);
#pragma pack(2)
				char *TransBuff = TranslateIP(ip);
				if (TransBuff)
					strcpy(pItems[i].CustomColumnData[0], TransBuff);
				strcat(pItems[i].CustomColumnData[0], ":");
				char buff[MIN_BUFF];
				memset(buff, 0, sizeof(buff));
				itoa(nPort, buff, 10);
				strcat(pItems[i].CustomColumnData[0], buff);
			}
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
		if (AutoRefresh == TRUE)
		{
			Info.Control(hPlugin, FCTL_UPDATEPANEL, (void *)TRUE);
			Info.Control(hPlugin, FCTL_REDRAWPANEL, NULL);
		}
	}
	return FALSE;
}
