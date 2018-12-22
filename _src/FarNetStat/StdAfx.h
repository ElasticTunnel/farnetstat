// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__EA605257_9C93_4937_95D0_913C2CCF570A__INCLUDED_)
#define AFX_STDAFX_H__EA605257_9C93_4937_95D0_913C2CCF570A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


// Insert your headers here
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#define _WINCON_      // предотвратить включение wincon.h
#include <windows.h>
#undef _WINCON_
#include "plugin.hpp" // этот файл хочет 1-byte alignment
#pragma pack(8)
#include <wincon.h>   // этот файл хочет 8-bytes alignment
#include <malloc.h>
#include <Winsock2.h>
#include <Iphlpapi.h>


// TODO: reference additional headers your program requires here

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__EA605257_9C93_4937_95D0_913C2CCF570A__INCLUDED_)
