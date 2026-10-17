import re,sys
t=open(sys.argv[1],errors="replace").read()
blocks=t.split("# Begin Source File")[1:]
out=[]
for b in blocks:
    m=re.search(r"SOURCE=\.\\([\w.]+)",b)
    if not m or not m.group(1).endswith(".c"): continue
    name=m.group(1)
    # per-config conditionals: find the section for GL Release
    sec=re.search(r"\"\$\(CFG\)\" == \"winquake - Win32 GL Release\"(.*?)(?=!ELSEIF|!ENDIF)",b,re.S)
    ex = bool(sec and "Exclude_From_Build 1" in sec.group(1))
    if not ex: out.append(name)
print(" ".join(out))
