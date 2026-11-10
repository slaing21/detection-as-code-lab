import json, sys
rec = json.load(open(sys.argv[1], encoding="utf-8-sig"))
event = json.loads(rec["_source"]["full_log"])
ed = event["win"]["eventdata"]
ed["parentImage"] = r"C:\Windows\System32\fodhelper.exe"
ed["parentCommandLine"] = "fodhelper.exe"
ed["image"] = r"C:\Windows\System32\cmd.exe"
ed["originalFileName"] = "Cmd.Exe"
print(json.dumps(event, separators=(",", ":")))