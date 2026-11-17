// Nintendo Switch Pro Controller, Joy-Cons, and 8BitDo controllers (Switch mode, VID 057E / 2DC8).
// Protocol reference: dekuNukem/Nintendo_Switch_Reverse_Engineering and Linux drivers/hid/hid-nintendo.c.
//
// Input report 0x30 (standard full report) contains real-time battery status in byte 2:
//   bit 4: charging
//   bits 7-5: level (0 = empty, 1 = critical, 2 = low, 3 = medium, 4 = full, scaled 0 to 8)
// Note: 8BitDo firmware returns a dummy static 0x40 (50%, not charging) in 0x21 subcommand replies,
// so 0x30 full reports are read directly to ensure accurate battery and charging status.
#include "drivers.h"

namespace {

bool IsSwitchController(USHORT vid, USHORT pid) {
    if (vid == 0x057E) {
        return pid == 0x2009 || pid == 0x2006 || pid == 0x2007 || pid == 0x200E || pid == 0x2017;
    }
    if (vid == 0x2DC8) {
        return true;
    }
    return false;
}

const wchar_t* SwitchControllerName(USHORT vid, USHORT pid) {
    if (vid == 0x057E) {
        switch (pid) {
            case 0x2006: return L"Joy-Con (L)";
            case 0x2007: return L"Joy-Con (R)";
            case 0x2009: return L"8BitDo / Switch Pro Controller";
            case 0x200E: return L"Joy-Con Charging Grip";
            case 0x2017: return L"SNES Controller";
            default: return L"Switch Controller";
        }
    }
    return L"8BitDo Controller";
}

}  // namespace

void PollNintendoSwitch(PollContext& ctx) {
    for (const auto& c : ctx.colls) {
        if (!IsSwitchController(c.vid, c.pid)) continue;
        if (c.page() != 0x01 || (c.usage() != 0x05 && c.usage() != 0x04)) continue;

        HidDev d;
        if (!d.Open(c)) continue;

        std::vector<BYTE> r;
        int pct = -1;
        bool charging = false, found = false;

        // 1. Read incoming standard streaming reports (0x30..0x33).
        // On 8BitDo and Switch controllers, these stream at 60Hz and carry the live battery byte.
        ULONGLONG end = GetTickCount64() + 300;
        while (!found && (LONGLONG)end - (LONGLONG)GetTickCount64() > 0) {
            if (d.Read(r, 60) < 3) continue;
            if (r[0] >= 0x30 && r[0] <= 0x33) {
                BYTE bat_con = r[2];
                int level = (bat_con & 0xE0) >> 4;
                charging = (bat_con & 0x10) != 0;
                pct = Clamp100((level * 100 + 4) / 8);
                found = true;
            }
        }

        // 2. If the controller is idle or in simple 0x3F mode, send subcommand 0x03 to request 0x30 mode.
        if (!found) {
            size_t outLen = c.outLen() > 0 ? c.outLen() : 49;
            std::vector<BYTE> out(outLen, 0);
            out[0] = 0x01;  // Output report ID
            out[1] = 0x01;  // Packet count
            out[2] = 0x00; out[3] = 0x01; out[4] = 0x40; out[5] = 0x40;
            out[6] = 0x00; out[7] = 0x01; out[8] = 0x40; out[9] = 0x40;
            out[10] = 0x03; // Subcommand 0x03: Set input report mode
            out[11] = 0x30; // Mode 0x30: Standard full mode
            d.Write(out);

            end = GetTickCount64() + 400;
            while (!found && (LONGLONG)end - (LONGLONG)GetTickCount64() > 0) {
                if (d.Read(r, 60) < 3) continue;
                if (r[0] >= 0x30 && r[0] <= 0x33) {
                    BYTE bat_con = r[2];
                    int level = (bat_con & 0xE0) >> 4;
                    charging = (bat_con & 0x10) != 0;
                    pct = Clamp100((level * 100 + 4) / 8);
                    found = true;
                } else if (r[0] == 0x21 && !found && r[2] != 0x40) {
                    // Only use 0x21 if it contains valid non-dummy telemetry
                    BYTE bat_con = r[2];
                    int level = (bat_con & 0xE0) >> 4;
                    charging = (bat_con & 0x10) != 0;
                    pct = Clamp100((level * 100 + 4) / 8);
                    found = true;
                }
            }
        }

        if (!found) continue;

        DeviceStatus s;
        UINT h = 2166136261u;
        for (wchar_t ch : c.path) { h ^= ch; h *= 16777619u; }
        s.key = L"switch:" + Hex4(c.pid) + L":" + std::to_wstring(h);
        s.name = HidProduct(c);
        if (s.name.empty() || s.name == L"Wireless Gamepad") {
            s.name = SwitchControllerName(c.vid, c.pid);
        }
        s.kind = DeviceKind::Gamepad;
        s.via = c.inLen() > 64 ? L"Bluetooth" : L"USB cable";
        s.percent = pct;
        s.charging = charging;
        ctx.out.push_back(s);
        ctx.Claim(c.vid, c.pid);
    }
}
