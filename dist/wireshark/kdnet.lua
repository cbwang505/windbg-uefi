-- KD over UDP network dissector
-- Run with: tshark -X lua_script:kdnet.lua

kdnet_proto = Proto("kdnet", "Windows Kernel Debugger over Network")

local hf = {}
function add_field(proto_field_constructor, name, desc, ...)
    local field_name = "kdnet." .. name
    -- If the description is omitted, use the name as label
    if type(desc) == "string" then
        hf[name] = proto_field_constructor(field_name, desc, ...)
    else
        hf[name] = proto_field_constructor(field_name, name, desc, ...)
    end
end
-- Convenience function to add many fields at once. The definition list contains
-- field types followed by (multiple) field names. An empty string can be used
-- for alignment.
-- Field types are integers, 64 is ULONG64, 16 is USHORT, etc.
function add_fields(defs)
    local typemap = {
        [64] = ProtoField.uint64,
        [32] = ProtoField.uint32,
        [16] = ProtoField.uint16,
        [8] = ProtoField.uint8,
    }
    local field_type
    local field_args = {}
    for _, def in ipairs(defs) do
        if type(def) == "number" then
            field_type = typemap[def] or ProtoField.bytes
        elseif type(def) == "table" then
            field_args = def
        elseif #def > 0 then
            add_field(field_type, def, table.unpack(field_args))
        end
    end
end
function add_fields_to_tree(defs, tvb, pinfo, tree, selection)
    local size
    if not selection then selection = {0, tvb:len()} end
    local offset, buffer_size = -selection[1], selection[2]
    for _, def in ipairs(defs) do
        if type(def) == "number" then
            size = def / 8
        elseif type(def) == "string" then
            if #def > 0 and offset >= 0 and offset + size <= buffer_size then
                assert(hf[def], "Unknown field " .. def)
                tree:add(hf[def], tvb(offset, size))
            end
            offset = offset + size
        end
    end
    return offset
end

-- KD serial protocol?
-- http://articles.sysprogs.org/kdvmware/kdcom.shtml
-- http://gr8os.googlecode.com/svn-history/r66/branches/0.2-devel/kernel/kd.cpp
-- http://www.developerfusion.com/article/84367/kernel-and-remote-debuggers/
-- add_field(ProtoField.string, "leader",  "Packet Leader")
-- add_field(ProtoField.uint16, "type",    "Packet Type", base.HEX_DEC)
-- add_field(ProtoField.uint16, "count",   "Byte Count", base.HEX_DEC)
-- add_field(ProtoField.uint32, "id",      "Packet Id", base.HEX_DEC)
-- add_field(ProtoField.uint32, "checksum", "Checksum", base.HEX)

-- KDNET
-- https://github.com/JumpCallPop/libKDNET
add_field(ProtoField.string, "magic",   "Magic")
add_field(ProtoField.uint8, "version",  "Protocol Version", base.HEX)
--[[Found these values for type (count, value for type field, ip.src):
     69 0x00000001      192.168.2.72
  57838 0x00000000      192.168.2.1
  57843 0x00000000      192.168.2.72
Full, smaller run (windbg-uncut):
    262 0x00000000      192.168.2.1
    265 0x00000000      192.168.2.72
    427 0x00000001      192.168.2.72
--]]--
add_field(ProtoField.uint8, "type",     "Type", base.HEX)
add_field(ProtoField.bytes, "data",     "Encrypted data")
add_field(ProtoField.bytes, "data_dec", "Decrypted data")

-- contents of encrypted blocks --
-- for type=0x00
add_field(ProtoField.uint32, "seqno",  "Seq no", base.HEX_DEC)
add_field(ProtoField.uint8, "tag",      "Tag", base.HEX)
-- _KD_PACKET_HEADER
local signature_values = {
    [0x62626262] = "Breakin",
    [0x30303030] = "Data",
    [0x69696969] = "Control",
}
local packet_type_values = {
    [0] = "UNUSED",
    [1] = "KD_STATE_CHANGE32",
    [2] = "KD_STATE_MANIPULATE",
    [3] = "KD_DEBUG_IO",
    [4] = "KD_ACKNOWLEDGE",
    [5] = "KD_RESEND",
    [6] = "KD_RESET",
    [7] = "KD_STATE_CHANGE64",
    [8] = "KD_POLL_BREAKIN",
    [9] = "KD_TRACE_IO",
    [10] = "KD_CONTROL_REQUEST",
    [11] = "KD_FILE_IO",
}
add_field(ProtoField.uint32, "signature", "Signature", base.HEX, signature_values)
add_field(ProtoField.uint16, "packet_type", "Packet Type", base.HEX_DEC, packet_type_values)
add_field(ProtoField.uint16, "total_data_length", "Total Data Length", base.DEC)
add_field(ProtoField.uint32, "packet_id", "Packet ID", base.DEC)
add_field(ProtoField.uint32, "checksum", "Checksum", base.HEX)
add_field(ProtoField.bytes,  "kd_data",  "Packet data")

-- from windbgkd.h
local apinumber_values = {
    -- Wait State Change Types
    [0x00003030] = "DbgKdMinimumStateChange",
    [0x00003030] = "DbgKdExceptionStateChange",
    [0x00003031] = "DbgKdLoadSymbolsStateChange",
    [0x00003032] = "DbgKdCommandStringStateChange",
    [0x00003033] = "DbgKdMaximumStateChange",
    -- Manipulate Types
    [0x00003130] = "DbgKdReadVirtualMemoryApi",
    [0x00003131] = "DbgKdWriteVirtualMemoryApi",
    [0x00003132] = "DbgKdGetContextApi",
    [0x00003133] = "DbgKdSetContextApi",
    [0x00003134] = "DbgKdWriteBreakPointApi",
    [0x00003135] = "DbgKdRestoreBreakPointApi",
    [0x00003136] = "DbgKdContinueApi",
    [0x00003137] = "DbgKdReadControlSpaceApi",
    [0x00003138] = "DbgKdWriteControlSpaceApi",
    [0x00003139] = "DbgKdReadIoSpaceApi",
    [0x0000313A] = "DbgKdWriteIoSpaceApi",
    [0x0000313B] = "DbgKdRebootApi",
    [0x0000313C] = "DbgKdContinueApi2",
    [0x0000313D] = "DbgKdReadPhysicalMemoryApi",
    [0x0000313E] = "DbgKdWritePhysicalMemoryApi",
    [0x0000313F] = "DbgKdQuerySpecialCallsApi",
    [0x00003140] = "DbgKdSetSpecialCallApi",
    [0x00003141] = "DbgKdClearSpecialCallsApi",
    [0x00003142] = "DbgKdSetInternalBreakPointApi",
    [0x00003143] = "DbgKdGetInternalBreakPointApi",
    [0x00003144] = "DbgKdReadIoSpaceExtendedApi",
    [0x00003145] = "DbgKdWriteIoSpaceExtendedApi",
    [0x00003146] = "DbgKdGetVersionApi",
    [0x00003147] = "DbgKdWriteBreakPointExApi",
    [0x00003148] = "DbgKdRestoreBreakPointExApi",
    [0x00003149] = "DbgKdCauseBugCheckApi",
    [0x00003150] = "DbgKdSwitchProcessor",
    [0x00003151] = "DbgKdPageInApi",
    [0x00003152] = "DbgKdReadMachineSpecificRegister",
    [0x00003153] = "DbgKdWriteMachineSpecificRegister",
    [0x00003154] = "OldVlm1",
    [0x00003155] = "OldVlm2",
    [0x00003156] = "DbgKdSearchMemoryApi",
    [0x00003157] = "DbgKdGetBusDataApi",
    [0x00003158] = "DbgKdSetBusDataApi",
    [0x00003159] = "DbgKdCheckLowMemoryApi",
    [0x0000315A] = "DbgKdClearAllInternalBreakpointsApi",
    [0x0000315B] = "DbgKdFillMemoryApi",
    [0x0000315C] = "DbgKdQueryMemoryApi",
    [0x0000315D] = "DbgKdSwitchPartition",
    [0x0000315E] = "DbgKdWriteCustomBreakpointApi",
    [0x0000315F] = "DbgKdGetContextExApi",
    [0x00003160] = "DbgKdSetContextExApi",
    -- Debug I/O Types
    [0x00003230] = "DbgKdPrintStringApi",
    [0x00003231] = "DbgKdGetStringApi",
    -- File I/O Types
    [0x00003430] = "DbgKdCreateFileApi",
    [0x00003431] = "DbgKdReadFileApi",
    [0x00003432] = "DbgKdWriteFileApi",
    [0x00003433] = "DbgKdCloseFileApi",
}
-- NTSTATUS codes, these are autogenerated and might not exist.
local ntstatus_values
pcall(function() ntstatus_values = dofile("ntstatus.lua") end)

-- DBGKD Structure for Wait State Change
add_field(ProtoField.uint32, "NewState", base.HEX, apinumber_values);
-- ProcessorLevel
-- Processor
add_field(ProtoField.uint32, "NumberProcessors")
add_field(ProtoField.uint64, "Thread", base.HEX)
add_field(ProtoField.uint64, "ProgramCounter", base.HEX)
-- (Exception)
add_field(ProtoField.int32, "ExceptionCode")
add_field(ProtoField.uint32, "ExceptionFlags", base.HEX)
add_field(ProtoField.uint64, "ExceptionRecord", base.HEX)
add_field(ProtoField.uint64, "ExceptionAddress", base.HEX)
add_field(ProtoField.uint32, "NumberParameters")
add_field(ProtoField.bytes, "ExceptionInformation")
add_field(ProtoField.uint32, "FirstChance")
-- (LoadSymbols)
add_field(ProtoField.uint32, "PathNameLength")
add_field(ProtoField.uint64, "BaseOfDll", base.HEX)
add_field(ProtoField.uint64, "ProcessId", base.HEX_DEC)
add_field(ProtoField.uint32, "CheckSum", base.HEX)
add_field(ProtoField.uint32, "SizeOfImage")
add_field(ProtoField.bool, "UnloadSymbols")
add_field(ProtoField.string, "PathName")
-- (CommandString)
add_field(ProtoField.uint32, "Flags", base.HEX)
add_field(ProtoField.uint32, "Reserved1", base.HEX)
add_field(ProtoField.bytes, "Reserved2")
add_field(ProtoField.string, "NameString")
add_field(ProtoField.string, "CommandString")
-- DBGKD Manipulate structure
add_field(ProtoField.uint32, "ApiNumber", base.HEX, apinumber_values)
add_field(ProtoField.uint16, "ProcessorLevel", base.HEX_DEC)
add_field(ProtoField.uint16, "Processor", base.HEX_DEC)
add_field(ProtoField.uint32, "ReturnStatus", base.HEX, ntstatus_values)
-- (ReadMemory/WriteMemory)
add_field(ProtoField.uint64, "TargetBaseAddress", base.HEX)
add_field(ProtoField.uint32, "TransferCount")
add_field(ProtoField.uint32, "ActualBytesRead")
add_field(ProtoField.uint32, "ActualBytesWritten")
add_field(ProtoField.uint32, "IoAddress", base.HEX)
add_field(ProtoField.uint32, "DataSize")
add_field(ProtoField.uint32, "DataValue", base.HEX)
add_field(ProtoField.bytes, "blob", "Extra data") -- invented name
-- (GetContext/SetContext)
add_field(ProtoField.uint64, "Offset")
add_field(ProtoField.uint32, "ByteCount")
add_field(ProtoField.uint32, "BytesCopied")
local context_defs = {
    {base.HEX},
    64, "P1Home", "P2Home", "P3Home", "P4Home", "P5Home", "P6Home",
    32, "ContextFlags", "MxCsr",
    16, "SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs",
    32, "EFlags",
    64, "Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7",
    "Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip",
    {},
    512*8, "XMM", -- XMM_SAVE_AREA32(512*8), XMM(26*128) fields
    26*128, "VectorRegister",
    {base.HEX},
    64, "VectorControl", "DebugControl",
    "LastBranchToRip", "LastBranchFromRip",
    "LastExceptionToRip", "LastExceptionFromRip",
}
add_fields(context_defs)
-- (Continue/Continue2)
add_field(ProtoField.uint32, "ContinueStatus", base.HEX, ntstatus_values)
add_field(ProtoField.uint32, "TraceFlag")
add_field(ProtoField.uint64, "Dr7", base.HEX)
add_field(ProtoField.uint64, "CurrentSymbolStart", base.HEX)
add_field(ProtoField.uint64, "CurrentSymbolEnd", base.HEX)
-- (RestoreBreakpoint)
add_field(ProtoField.uint32, "BreakPointHandle")
-- (GetVersion, DBGKD_GET_VERSION64)
local get_version64_defs = {
    16, "MajorVersion", "MinorVersion",
    8, "ProtocolVersion", "KdSecondaryVersion",
    {base.HEX},
    16, "version_Flags", "MachineType",
    {},
    8, "MaxPacketType", "MaxStateChange", "MaxManipulate", "Simulation",
    16, "",
    {base.HEX},
    64, "KernBase", "PsLoadedModuleList", "DebuggerDataList",

}
add_fields(get_version64_defs)
-- DBGKD Debug I/O structure
add_field(ProtoField.uint32, "LengthOfString")
add_field(ProtoField.uint32, "LengthOfPromptString")
add_field(ProtoField.uint32, "LengthOfStringRead")
add_field(ProtoField.string, "String")
add_field(ProtoField.string, "PromptString")
add_field(ProtoField.string, "StringRead")
-- File I/O Structure
add_field(ProtoField.uint32, "Status", base.HEX, ntstatus_values)
add_field(ProtoField.uint32, "DesiredAccess", base.HEX)
add_field(ProtoField.uint32, "FileAttributes", base.HEX)
add_field(ProtoField.uint32, "ShareAccess", base.HEX)
add_field(ProtoField.uint32, "CreateDisposition", base.HEX)
add_field(ProtoField.uint32, "CreateOptions", base.HEX)
add_field(ProtoField.uint64, "Handle", base.HEX)
add_field(ProtoField.uint64, "Length")
add_field(ProtoField.string, "FileData")

-- for type=0x01
add_field(ProtoField.bytes,  "field1",  "Zeroes")
add_field(ProtoField.uint16, "uptime",  "Uptime", base.DEC)
add_field(ProtoField.bytes,  "field2",  "Unknown")
add_field(ProtoField.bytes,  "field3",  "Unknown (begin key material)")
add_field(ProtoField.uint32, "seqno2",  "Seq no", base.HEX_DEC)
add_field(ProtoField.bytes,  "random",  "Random")
add_field(ProtoField.ipv6,   "src_addr", "Source Addr")
add_field(ProtoField.uint16, "src_port", "Source Port", base.DEC)
add_field(ProtoField.ipv6,   "dst_addr", "Dest   Addr")
add_field(ProtoField.uint16, "dst_port", "Dest   Port", base.DEC)
add_field(ProtoField.ipv6,   "unk_addr", "Unknwn Addr")
add_field(ProtoField.uint16, "unk_port", "Unknwn Port", base.DEC)
add_field(ProtoField.bytes,  "padding",  "Padding")
kdnet_proto.fields = hf

kdnet_proto.prefs.key = Pref.string("Decryption key", "",
    "A 256-bit decryption key formatted as w.x.y.z (components are in base-36)")

-----
-- Decryption routine.
-----
-- For other locations, use: LUA_CPATH=.../luagcrypt/?.so
local gcrypt = require("luagcrypt")
gcrypt.init()
function decrypt(key, data)
    local iv = string.sub(data, -16)
    local ciphertext = string.sub(data, 1, -17)
    local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES256, gcrypt.CIPHER_MODE_CBC)
    cipher:setkey(key)
    cipher:setiv(iv)
    return cipher:decrypt(ciphertext)
end
-----
-- Key preparation
-----
function dotted_key(s)
    local key = '';
    for p in string.gmatch(s, "[0-9a-z]+") do
        local n = tonumber(p, 36);
        assert(n < 2^64, "Invalid key")
        local part = '';
        while n > 0 do
            part = string.char(n % 0x100) .. part;
            n = math.floor(n / 0x100);
        end
        key = key .. part .. string.rep('\0', 8 - string.len(part))
    end
    assert(string.len(key) == 32, "Invalid key format")
    return key
end
function data_key(initial_key, decrypted_data)
    -- key for Debugger -> Debuggee data flows
    local blob = string.sub(decrypted_data, 8+1, 8+322)
    local md = gcrypt.Hash(gcrypt.MD_SHA256)
    md:write(initial_key)
    md:write(blob)
    local key = md:read()
    assert(string.len(key) == 32, "Invalid key format")
    return key
end
----

local session_keys = {}
function kdnet_stored_key(pinfo, new_key)
    if new_key then
        session_keys[pinfo.number] = new_key
    else
        -- Use the most recent key relatively to the current packet
        local i_highest = -1, key
        for i, v in pairs(session_keys) do
            if i_highest < i and i < pinfo.number then
                i_highest = i
                key = v
            end
        end
        return key
    end
end

function dissect_kdnet_data(tvb, pinfo, pkt_type, tree)
    if tvb:raw(0, 3) ~= '\0\0\0' then
        return
    end
    if pkt_type == 0x00 then
        dissect_kdnet_0x00_data(tvb, pinfo, tree)
    elseif pkt_type == 0x01 then
        dissect_kdnet_init_data(tvb, pinfo, tree)
    end
end

-- State Change dissections
function dissect_kd_state_change_Exception(tvb, pinfo, tree, from_debugger, word_size)
    tree:add_le(hf.ExceptionCode,    tvb(0, 4))
    tree:add_le(hf.ExceptionFlags,   tvb(4, 4))
    tree:add_le(hf.ExceptionRecord,  tvb(8, word_size))
    tree:add_le(hf.ExceptionAddress, tvb(8 + word_size, word_size))
    tree:add_le(hf.NumberParameters, tvb(8 + word_size * 2, 4))
    local except_info_offset = word_size == 8 and 0x20 or 0x16
    tree:add_le(hf.ExceptionInformation, tvb(except_info_offset, word_size * 15))
    tree:add_le(hf.FirstChance, tvb(except_info_offset + word_size * 15, 4))
end
function dissect_kd_state_change_LoadSymbols(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    local offset
    tree:add_le(hf.PathNameLength, tvb(0, 4))
    local path_name_length = tvb(0, 4):le_uint()
    tree:add_le(hf.BaseOfDll,      tvb(4, word_size))
    tree:add_le(hf.ProcessId,      tvb(word_size * 2, word_size))
    tree:add_le(hf.CheckSum,       tvb(word_size * 3, 4))
    tree:add_le(hf.SizeOfImage,    tvb(word_size * 3 + 4, 4))
    tree:add_le(hf.UnloadSymbols,  tvb(word_size * 3 + 8, 1))
    if path_name_length > 0 then
        tree:add_le(hf.PathName, tvb(extradata_offset, path_name_length))
    end
end
function dissect_kd_state_change_CommandString(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add(hf.Flags, tvb(0, 4))
    tree:add(hf.Reserved1, tvb(4, 4))
    tree:add(hf.Reserved2, tvb(8, 7*8))
    if tvb:len() > extradata_offset then
        -- Assume terminating NULs for each string (throw exceptions otherwise).
        local name_len = #tvb(extradata_offset):stringz()
        tree:add(hf.NameString, tvb(extradata_offset, name_len))
        local command_offset = extradata_offset + name_len + 1
        local command_len = tvb:len() - 1 - command_offset
        tree:add(hf.CommandString, tvb(command_offset, command_len))
    end
end

function dissect_kd_state_change(tvb, pinfo, tree)
    local word_size = 8 -- 4 or 8 (for 32 or 64-bit)
    tree:add_le(hf.NewState, tvb(0, 4))
    local new_state = tvb(0, 4):le_uint()
    pinfo.cols.info:set(apinumber_values[new_state] or "")
    tree:add_le(hf.ProcessorLevel, tvb(4, 2))
    tree:add_le(hf.Processor, tvb(6, 2))
    tree:add_le(hf.NumberProcessors, tvb(8, 4))
    local offset = word_size == 8 and 16 or 12
    tree:add_le(hf.Thread, tvb(offset, word_size))
    offset = offset + word_size
    tree:add_le(hf.ProgramCounter, tvb(offset, word_size))
    offset = offset + word_size
    -- sizeof(DBGKD_ANY_WAIT_STATE_CHANGE) is sum of largest fields:
    -- DBGKM_EXCEPTION64(0xa0), followed by AMD64_DBGKD_CONTROL_REPORT(0x30)
    local extradata_offset = (word_size == 8 and 0xa0 or 0x56) + 0x30
    -- TODO ControlReport, AnyControlReport
    local subdissector = ({
        [0x00003030] = dissect_kd_state_change_Exception,
        [0x00003031] = dissect_kd_state_change_LoadSymbols,
        [0x00003032] = dissect_kd_state_change_CommandString,
    })[new_state]
    if subdissector then
        subdissector(tvb(offset), pinfo, tree, from_debugger, word_size, extradata_offset)
    end
end

-- Manipulate API dissections
function dissect_kd_manipulate_ReadMemory(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add_le(hf.TargetBaseAddress, tvb(0, word_size))
    tree:add_le(hf.TransferCount,     tvb(word_size, 4))
    tree:add_le(hf.ActualBytesRead,   tvb(word_size + 4, 4))
    if not from_debugger and tvb:len() > extradata_offset then
        local actual_bytes_read = tvb(word_size + 4, 4):le_uint()
        tree:add_le(hf.blob, tvb(extradata_offset, actual_bytes_read))
    end
end
function dissect_kd_manipulate_WriteMemory(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add_le(hf.TargetBaseAddress, tvb(0, word_size))
    tree:add_le(hf.TransferCount,     tvb(word_size, 4))
    tree:add_le(hf.ActualBytesWritten, tvb(word_size + 4, 4))
    if from_debugger and tvb:len() > extradata_offset then
        local transfer_count = tvb(word_size, 4):le_uint()
        tree:add_le(hf.blob, tvb(extradata_offset, transfer_count))
    end
end
function dissect_kd_manipulate_GetContext(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    if tvb:len() > extradata_offset then
        add_fields_to_tree(context_defs, tvb(extradata_offset), pinfo, tree)
    end
end
local dissect_kd_manipulate_SetContext = dissect_kd_manipulate_GetContext
function dissect_kd_manipulate_RestoreBreakpoint(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add_le(hf.BreakPointHandle, tvb(0, 4))
end
function dissect_kd_manipulate_Continue(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add_le(hf.ContinueStatus, tvb(0, 4))
end
local dissect_kd_manipulate_ReadControlSpace = dissect_kd_manipulate_ReadMemory
local dissect_kd_manipulate_WriteControlSpace = dissect_kd_manipulate_WriteMemory
function dissect_kd_manipulate_ReadIoSpace(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add_le(hf.IoAddress, tvb(0, 4))
    tree:add_le(hf.DataSize,  tvb(4, 4))
    tree:add_le(hf.DataValue, tvb(8, 4))
end
local dissect_kd_manipulate_WriteIoSpace = dissect_kd_manipulate_ReadIoSpace
function dissect_kd_manipulate_Continue2(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add_le(hf.ContinueStatus, tvb(0, 4))
    -- AMD64_DBGKD_CONTROL_SET
    tree:add_le(hf.TraceFlag,           tvb(0, 4))
    tree:add_le(hf.Dr7,                 tvb(4, 8))
    tree:add_le(hf.CurrentSymbolStart,  tvb(12, 8))
    tree:add_le(hf.CurrentSymbolEnd,    tvb(20, 8))
end
-- TODO ActualBytesRead in request is actually CacheFlags
local dissect_kd_manipulate_ReadPhysicalMemory = dissect_kd_manipulate_ReadMemory
-- TODO ActualBytesWritten in request is actually CacheFlags
local dissect_kd_manipulate_WritePhysicalMemory = dissect_kd_manipulate_WriteMemory
function dissect_kd_manipulate_GetVersion(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    if not from_debugger then
        add_fields_to_tree(get_version64_defs, tvb, pinfo, tree)
    end
end
function dissect_kd_manipulate_GetContextEx(tvb, pinfo, tree, from_debugger, word_size, extradata_offset)
    tree:add_le(hf.Offset, tvb(0, 4))
    tree:add_le(hf.ByteCount, tvb(4, 4))
    tree:add_le(hf.BytesCopied, tvb(8, 4))
    if tvb:len() > extradata_offset then
        add_fields_to_tree(context_defs, tvb(extradata_offset), pinfo, tree,
            {tvb(0, 4):le_uint(), tvb(8, 4):le_uint()})
    end
end

function dissect_kd_state_manipulate(tvb, pinfo, tree, from_debugger)
    local word_size = 8 -- 4 or 8 (for 32 or 64-bit)
    tree:add_le(hf.ApiNumber, tvb(0, 4))
    local api_number = tvb(0, 4):le_uint()
    pinfo.cols.info:set(apinumber_values[api_number] or "")
    tree:add_le(hf.ProcessorLevel, tvb(4, 2))
    tree:add_le(hf.Processor, tvb(6, 2))
    tree:add_le(hf.ReturnStatus, tvb(8, 4))
    -- TODO is sizeof(DBGKD_MANIPULATE_STATE32)==0x28 too?
    local extradata_offset = word_size == 8 and 0x28 or 0x28
    local subdissector = ({
        [0x00003130] = dissect_kd_manipulate_ReadMemory,
        [0x00003131] = dissect_kd_manipulate_WriteMemory,
        [0x00003132] = dissect_kd_manipulate_GetContext,
        [0x00003133] = dissect_kd_manipulate_SetContext,
        [0x00003135] = dissect_kd_manipulate_RestoreBreakpoint,
        [0x00003136] = dissect_kd_manipulate_Continue,
        [0x00003137] = dissect_kd_manipulate_ReadControlSpace,
        [0x00003138] = dissect_kd_manipulate_WriteControlSpace,
        [0x00003139] = dissect_kd_manipulate_ReadIoSpace,
        [0x0000313a] = dissect_kd_manipulate_WriteIoSpace,
        [0x0000313c] = dissect_kd_manipulate_Continue2,
        [0x0000313d] = dissect_kd_manipulate_ReadPhysicalMemory,
        [0x0000313e] = dissect_kd_manipulate_WritePhysicalMemory,
        [0x00003146] = dissect_kd_manipulate_GetVersion,
        [0x0000315f] = dissect_kd_manipulate_GetContextEx,
    })[api_number]
    if subdissector then
        subdissector(tvb(8 + word_size), pinfo, tree, from_debugger, word_size, extradata_offset)
    end
end

function dissect_kd_debug_io(tvb, pinfo, tree, from_debugger)
    tree:add_le(hf.ApiNumber, tvb(0, 4))
    pinfo.cols.info:set(apinumber_values[tvb(0, 4):le_uint()] or "")
    tree:add_le(hf.ProcessorLevel, tvb(4, 2))
    tree:add_le(hf.Processor, tvb(6, 2))
    local api_number = tvb(0, 4):le_uint()
    if api_number == 0x00003230 then -- DbgKdPrintStringApi
        tree:add_le(hf.LengthOfString, tvb(8, 4))
        tree:add(hf.String, tvb(16, tvb(8, 4):le_uint()))
    elseif api_number == 0x00003231 then -- DbgKdGetStringApi
        tree:add_le(hf.LengthOfPromptString, tvb(8, 4))
        tree:add_le(hf.LengthOfStringRead, tvb(12, 4))
        if from_debugger then
            tree:add(hf.StringRead, tvb(16, tvb(12, 4):le_uint()))
        else
            tree:add(hf.PromptString, tvb(16, tvb(8, 4):le_uint()))
        end
    end
end

function dissect_kd_file_io(tvb, pinfo, tree)
    tree:add_le(hf.ApiNumber, tvb(0, 4))
    pinfo.cols.info:set(apinumber_values[tvb(0, 4):le_uint()] or "")
    tree:add_le(hf.Status, tvb(4, 4))
    local api_number = tvb(0, 4):le_uint()
    if api_number == 0x00003430 then -- DbgKdCreateFileApi
        tree:add_le(hf.DesiredAccess, tvb(8, 4))
        tree:add_le(hf.FileAttributes, tvb(12, 4))
        tree:add_le(hf.ShareAccess, tvb(16, 4))
        tree:add_le(hf.CreateDisposition, tvb(20, 4))
        tree:add_le(hf.CreateOptions, tvb(24, 4))
        tree:add_le(hf.Handle, tvb(24, 8))
        tree:add_le(hf.Length, tvb(32, 8))
        if tvb:len() > 64 then
            -- Observed to be a file path for DbgKdCreateFileApi
            tree:add_packet_field(hf.FileData, tvb(64), ENC_UTF_16+ENC_LITTLE_ENDIAN)
        end
    end
end

function dissect_kd_header(tvb, pinfo, tree, from_debugger)
    tree:add(hf.signature, tvb(0, 4))
    tree:add_le(hf.packet_type, tvb(4, 2))
    tree:add_le(hf.total_data_length, tvb(6, 2))
    tree:add_le(hf.packet_id, tvb(8, 4))
    tree:add_le(hf.checksum, tvb(12, 4))
    pinfo.cols.info:set(packet_type_values[tvb(4, 2):le_uint()] or "")
    local datalen = tvb(6, 2):le_uint()
    if datalen > 0 then
        local packet_type = tvb(4, 2):le_uint()
        local data_tvb = tvb:range(16, datalen)
        local subtree = tree:add(hf.kd_data, data_tvb)
        local subdissector = ({
            [0x0001] = dissect_kd_state_change, -- 32
            [0x0002] = dissect_kd_state_manipulate,
            [0x0003] = dissect_kd_debug_io,
            [0x0007] = dissect_kd_state_change, -- 64
            [0x000b] = dissect_kd_file_io,
        })[packet_type]
        if subdissector then
            subdissector(data_tvb, pinfo, subtree, from_debugger)
        end
    end
end

function dissect_kdnet_0x00_data(tvb, pinfo, tree)
    tree:add(hf.field1, tvb(0, 3))
    tree:add(hf.seqno, tvb(3, 4))
    -- if tag & 0x80, then direction debugger -> debuggee
    tree:add(hf.tag, tvb(7, 1))
    local from_debugger = bit.band(tvb(7, 1):uint(), 0x80) ~= 0
    dissect_kd_header(tvb:range(8), pinfo, tree, from_debugger)
    pinfo.cols.info:prepend(from_debugger and "<" or ">")
end

function dissect_kdnet_pipe_data(tvb, pinfo, tree)
     local from_debugger = 1
    dissect_kd_header(tvb, pinfo, tree, from_debugger)
    pinfo.cols.info:prepend(from_debugger and "<" or ">")
end

function dissect_kdnet_init_data(tvb, pinfo, tree)
    tree:add(hf.field1, tvb(0, 3))
    tree:add(hf.uptime, tvb(3, 4))
    tree:add(hf.field2, tvb(7, 2))
    tree:add(hf.field3, tvb(9, 1))
    -- Possibly as session identifier? The debuggee keeps sending these packets
    -- (with kdnet.field==0x0001, kdnet.field3==0x01), at some point debugger
    -- sends kdnet.field==0x8601, kdnet.field3==0x02 with presumably key data.
    tree:add_le(hf.seqno2, tvb(10, 2))
    tree:add(hf.random, tvb(12, 30))
    tree:add(hf.src_addr, tvb(42, 16))
    tree:add(hf.src_port, tvb(58, 2))
    tree:add(hf.dst_addr, tvb(60, 16))
    tree:add(hf.dst_port, tvb(76, 2))
    tree:add(hf.unk_addr, tvb(78, 16))
    tree:add(hf.unk_port, tvb(90, 2))
    tree:add(hf.padding, tvb(92))
end

function kdnet_proto.dissector(tvb, pinfo, tree)
    -- Ignore packets not starting with "MDBG"
    if tvb(0, 4):uint() ~= 0x4d444247 then
        pinfo.cols.protocol = "KDNET"
        dissect_kdnet_pipe_data(tvb, pinfo, tree)
        return tvb:len()      
    end
    local decryption_key;
    if kdnet_proto.prefs.key ~= "" then
        decryption_key = dotted_key(kdnet_proto.prefs.key);
    end

    pinfo.cols.protocol = "KDNET"
    local subtree = tree:add(kdnet_proto, tvb())
    subtree:add(hf.magic, tvb(0, 4))
    subtree:add(hf.version, tvb(4, 1))
    subtree:add(hf.type, tvb(5, 1))
    subtree:add(hf.data, tvb(6))
    local pkt_type = tvb(5, 1):uint()

    if pkt_type == 0x00 then
        decryption_key = kdnet_stored_key(pinfo)
    end

    if decryption_key then
        local enc_data = tvb:raw(6)
        local decrypted_bytes = decrypt(decryption_key, enc_data)
        local dec_data = ByteArray.new(decrypted_bytes, true)
            :tvb("Decrypted KDNET data")
        if pkt_type == 0x01 and dec_data(7, 1):uint() == 0x86 then
            local key = data_key(decryption_key, decrypted_bytes)
            kdnet_stored_key(pinfo, key)
        end
        local subtree_dec = subtree:add(hf.data_dec, dec_data())
        dissect_kdnet_data(dec_data, pinfo, pkt_type, subtree_dec)
    end

    -- pinfo.cols.protocol = "KD"
    -- subtree:add(hf.leader, tvb(0, 4))
    -- subtree:add(hf.type, tvb(4, 2))
    -- subtree:add(hf.count, tvb(6, 2))
    -- subtree:add(hf.id, tvb(8, 4))
    -- subtree:add(hf.checksum, tvb(12, 4))
    return tvb:len()
end

function kdnet_proto.init()
    -- Reset session keys between captures
    session_keys = {}
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(51111, kdnet_proto)
kdnet_proto:register_heuristic("udp", kdnet_proto.dissector)

-- vim: set sw=4 ts=4 et:
