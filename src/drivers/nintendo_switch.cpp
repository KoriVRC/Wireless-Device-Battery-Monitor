// Nintendo Switch Pro Controller, Joy-Cons, and 8BitDo controllers (Switch mode, VID 057E / 2DC8).
// Protocol reference: dekuNukem/Nintendo_Switch_Reverse_Engineering and Linux drivers/hid/hid-nintendo.c.
//
// Input report 0x21 / 0x30 contains battery status in byte 2:
//   bit 4: charging
//   bits 7-5: level (0 = empty, 1 = critical, 2 = low, 3 = medium, 4 = full, scaled 0 to 8)
// An output report 0x01 with subcommand 0x02 (request device info) prompts an immediate 0x21 reply.
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

        // Send subcommand 0x02 (request device info) via Output Report 0x01
        // to prompt an immediate 0x21 status reply with battery data.
        size_t outLen = c.outLen() > 0 ? c.outLen() : 49;
        std::vector<BYTE> out(outLen, 0);
        out[0] = 0x01;  // Output report ID
        out[1] = 0x01;  // Packet count
        out[2] = 0x00; out[3] = 0x01; out[4] = 0x40; out[5] = 0x40;  // Neutral rumble L
        out[6] = 0x00; out[7] = 0x01; out[8] = 0x40; out[9] = 0x40;  // Neutral rumble R
        out[10] = 0x02; // Subcommand: request device info
        d.Write(out);

        std::vector<BYTE> r;
        int pct = -1;
        bool charging = false, found = false;
        ULONGLONG end = GetTickCount64() + 600;
        while (!found && (LONGLONG)end - (LONGLONG)GetTickCount64() > 0) {
            if (d.Read(r, 100) < 3) continue;
            // Report 0x21 (subcommand reply) or 0x30 / 0x31 / 0x32 / 0x33 (full reports)
            if (r[0] == 0x21 || (r[0] >= 0x30 && r[0] <= 0x33)) {
                BYTE bat_con = r[2];
                int level = (bat_con & 0xE0) >> 4;
                charging = (bat_con & 0x10) != 0;
                // Level is reported 0 to 8 (8 = 100%, 6 = 75%, 4 = 50%, 2 = 25%, 0 = 0%)
                pct = Clamp100((level * 100 + 4) / 8);
                found = true;
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
