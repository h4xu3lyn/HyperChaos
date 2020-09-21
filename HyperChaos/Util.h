#pragma once
#include "extern.h"

BOOL HvUtilBitIsSet(SIZE_T BitField, SIZE_T BitPosition);

SIZE_T HvUtilBitSetBit(SIZE_T BitField, SIZE_T BitPosition);

SIZE_T HvUtilBitClearBit(SIZE_T BitField, SIZE_T BitPosition);

SIZE_T HvUtilBitGetBitRange(SIZE_T BitField, SIZE_T BitMax, SIZE_T BitMin);

SIZE_T HvUtilEncodeMustBeBits(SIZE_T DesiredValue, SIZE_T ControlMSR);

VOID HvUtilLog(LPCSTR MessageFormat, ...);

VOID HvUtilLogDebug(LPCSTR MessageFormat, ...);

VOID HvUtilLogSuccess(LPCSTR MessageFormat, ...);

VOID HvUtilLogError(LPCSTR MessageFormat, ...);

#define FOR_EACH_LIST_ENTRY(_LISTHEAD_, _LISTHEAD_NAME_, _TARGET_TYPE_, _TARGET_NAME_) \
	for (PLIST_ENTRY Entry = _LISTHEAD_->_LISTHEAD_NAME_.Flink; Entry != &_LISTHEAD_->_LISTHEAD_NAME_; Entry = Entry->Flink) { \
	P##_TARGET_TYPE_ _TARGET_NAME_ = CONTAINING_RECORD(Entry, _TARGET_TYPE_, _LISTHEAD_NAME_);

# define FOR_EACH_LIST_ENTRY_END() }