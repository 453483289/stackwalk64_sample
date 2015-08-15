// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#include "ModInfo.h"

#include <stdio.h>
#include <tchar.h>

#include <boost/python.hpp>
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>

#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
// TODO: reference additional headers your program requires here

extern "C" {
	#include "DbgHelp.h"
	#include "intrin.h"
}
